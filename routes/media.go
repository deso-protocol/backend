package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	// We import this so that we can decode gifs.
	_ "image/gif"

	// We import this so that we can decode pngs.
	_ "image/png"

	"cloud.google.com/go/storage"
	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/h2non/bimg"
	"google.golang.org/api/option"
)

// GetGCSClient ...
func (fes *APIServer) GetGCSClient(ctx context.Context) (*storage.Client, error) {
	// If we have credentials, use them.  Otherwise, return a client without authentication.
	if fes.Config.GCPCredentialsPath != "" {
		return storage.NewClient(ctx, option.WithCredentialsFile(fes.Config.GCPCredentialsPath))
	} else {
		return storage.NewClient(ctx, option.WithoutAuthentication())
	}
}

func (fes *APIServer) uploadSingleImage(image string, extension string) (_imageURL string, _err error) {
	// Set up gcp storage client
	ctx := context.Background()
	client, err := fes.GetGCSClient(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	bucketName := fes.Config.GCPBucketName
	var dec io.Reader
	var imageFileName string

	if extension != ".gif" {
		var imageBytes []byte
		imageBytes, err = resizeAndConvertFromEncodedImageContent(image, 1000)
		if err != nil {
			return "", err
		}
		dec = bytes.NewBuffer(imageBytes)
		imageFileName = getImageHex(string(imageBytes)) + ".webp"
	} else {
		dec = base64.NewDecoder(base64.StdEncoding,
			strings.NewReader(image))
		imageFileName = getImageHex(image) + ".gif"
	}
	// Create writer and then copy the content of the decoder into the writer.
	wc := client.Bucket(bucketName).Object(imageFileName).NewWriter(ctx)
	if _, err = io.Copy(wc, dec); err != nil {
		return "", err
	}

	if err = wc.Close(); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%v/%v", fes.Config.GCPBucketName, imageFileName), nil
}

func getEncodedImageContent(encodedImageString string) string {
	return encodedImageString[strings.Index(encodedImageString, ",")+1:]
}

func resizeAndConvertToWebp(encodedImageString string, maxDim uint) (_image []byte, _err error) {
	// Extract the relevant portion of the base64 encoded string and process the image.
	encodedImageContent := getEncodedImageContent(encodedImageString)
	return resizeAndConvertFromEncodedImageContent(encodedImageContent, maxDim)

}

func resizeAndConvertFromEncodedImageContent(encodedImageContent string, maxDim uint) (_image []byte, _err error) {
	// always strip metadata
	processOptions := bimg.Options{StripMetadata: true}
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedImageContent)
	imgBytes, err := bimg.NewImage(decodedBytes).Process(processOptions)
	if err != nil {
		return nil, err
	}
	img := bimg.NewImage(imgBytes)

	// resize the image
	resizedImage, err := _resizeImage(img, maxDim)
	if err != nil {
		return nil, err
	}
	return resizedImage.Convert(bimg.WEBP)
}

type UploadImageResponse struct {
	// Location of the image after upload
	ImageURL string
}

// Upload image before submitting post ...
func (fes *APIServer) UploadImage(ww http.ResponseWriter, req *http.Request) {
	err := req.ParseMultipartForm(10 << 20)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: Problem parsing multipart form data: %v", err))
		return
	}

	JWT := req.Form["JWT"]
	userPublicKey := req.Form["UserPublicKeyBase58Check"]
	if len(JWT) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("No JWT provided"))
		return
	}
	if len(userPublicKey) == 0 {
		_AddBadRequestError(ww, fmt.Sprintf("No public key provided"))
		return
	}
	isValid, err := fes.ValidateJWT(userPublicKey[0], JWT[0])
	if !isValid {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: Invalid token: %v", err))
		return
	}

	file, fileHeader, err := req.FormFile("file")
	if file != nil {
		defer file.Close()
	}
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: Problem getting file from form data: %v", err))
		return
	}
	if fileHeader.Size > MaxRequestBodySizeBytes {
		_AddBadRequestError(ww, fmt.Sprintf("File too large."))
		return
	}
	fileExtension, err := mapMimeTypeToExtension(fileHeader.Header.Get("Content-Type"))
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: problem extracting file extension: %v", err))
		return
	}
	buf := bytes.NewBuffer(nil)
	if _, err = io.Copy(buf, file); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: problem copying file to buffer: %v", err))
		return
	}

	encodedFileString := base64.StdEncoding.EncodeToString(buf.Bytes())
	imageURL, err := fes.uploadSingleImage(encodedFileString, fileExtension)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: problem uploading image: %v", err))
		return
	}

	// Return all the data associated with the transaction in the response
	res := UploadImageResponse{
		ImageURL: imageURL,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadImage: Problem encoding response as JSON: %v", err))
		return
	}
}

func mapMimeTypeToExtension(mimeType string) (string, error) {
	switch mimeType {
	case "image/gif":
		return ".gif", nil
	case "image/jpeg":
		return ".jpeg", nil
	case "image/png":
		return ".png", nil
	case "image/webp":
		return ".webp", nil
	}
	return "", fmt.Errorf("Mime type not supported: %v", mimeType)
}

// getImageHex ...
func getImageHex(base64EncodedImage string) string {
	return hex.EncodeToString(chainhash.HashB([]byte(base64EncodedImage)))
}

func preprocessExtraData(extraData map[string]string) map[string][]byte {
	extraDataProcessed := make(map[string][]byte)
	for k, v := range extraData {
		if len(v) > 0 {
			extraDataProcessed[k] = []byte(v)
		}
	}
	return extraDataProcessed
}

func _resizeImage(imageObj *bimg.Image, maxDim uint) (_imgObj *bimg.Image, _err error) {
	// Get the width and height.
	imgSize, err := imageObj.Size()
	if err != nil {
		return nil, err
	}
	imgWidth := imgSize.Width
	imgHeight := imgSize.Height

	// Resize the image based on which side is longer. Doing it this way preserves the
	// image's aspect ratio while making sure it isn't too large.
	var resizedImageBytes []byte
	newWidth := imgWidth
	newHeight := imgHeight
	if imgWidth > imgHeight {
		if newWidth >= int(maxDim) {
			newWidth = int(maxDim)
			newHeight = int(float64(imgHeight) * float64(newWidth) / float64(imgWidth))
		}
	} else {
		if newHeight >= int(maxDim) {
			newHeight = int(maxDim)
			newWidth = int(float64(imgWidth) * float64(newHeight) / float64(imgHeight))
		}
	}
	resizedImageBytes, err = imageObj.Resize(newWidth, newHeight)
	if err != nil {
		return nil, err
	}
	resizedImage := bimg.NewImage(resizedImageBytes)
	return resizedImage, nil
}

type GetFullTikTokURLRequest struct {
	TikTokShortVideoID string
}

type GetFullTikTokURLResponse struct {
	FullTikTokURL string
}

func (fes *APIServer) GetFullTikTokURL(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetFullTikTokURLRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetFullTikTokURL: Problem parsing request body: %v", err))
		return
	}
	tiktokURL := fmt.Sprintf("https://vm.tiktok.com/%v", requestData.TikTokShortVideoID)
	// Make sure the url matches the TikTok short URL regex.
	if !lib.TikTokShortURLRegex.Match([]byte(tiktokURL)) {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetFullTikTokURL: TikTokShortVideoURL does not conform to regex: %v", tiktokURL))
		return
	}
	// Create a new HTTP Client, create the request, and perform the GET request.
	client := &http.Client{}
	req, err := http.NewRequest("GET", tiktokURL, nil)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetFullTikTokURL: creating GET request: %v", err))
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetFullTikTokURL: error performing GET request: %v", err))
		return
	}
	// If the response is not a 200 or 302, raise an error.
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		_AddBadRequestError(ww, fmt.Sprintf("GetFullTikTokURL: GET request did not return 200 or 302 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	finalURL := resp.Request.URL
	// If we didn't get the final destination URL, that is an error.
	if finalURL == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetFullTikTokURL: response did not include redirected url"))
		return
	}

	// Convert the final URL to a string and verify that it meets the full TikTok URL regex.
	fullURL := finalURL.String()
	if !lib.TikTokFullURLRegex.Match([]byte(fullURL)) {
		_AddBadRequestError(ww, fmt.Sprintf("GetFullTikTokURL: destination url did not conform to tiktok full URL format: %v", fullURL))
		return
	}

	res := GetFullTikTokURLResponse{
		FullTikTokURL: fullURL,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("TikTokMobileCurl: Problem encoding response as JSON: %v", err))
		return
	}
}
