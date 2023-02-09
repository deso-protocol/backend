package routes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	// We import this so that we can decode gifs.
	_ "image/gif"

	// We import this so that we can decode pngs.
	_ "image/png"

	// We import this so that we can determine the length of mp4s
	"gopkg.in/vansante/go-ffprobe.v2"

	"cloud.google.com/go/storage"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/deso-protocol/core/lib"
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

type LivepeerResponse struct {
	TusEndpoint string `json:"tusEndpoint"`
	Url         string `json:"url"`
	Asset       struct {
		Id         string `json:"id"`
		PlaybackId string `json:"playbackId"`
	} `json:"asset"`
}

// UploadVideo validates that a file is a valid upload file, requests an upload URL from livepeer, and uploads
// that file to livepeer.
func (fes *APIServer) UploadVideo(ww http.ResponseWriter, req *http.Request) {
	// Ensure that livepeer token is present in config.
	if fes.Config.LivepeerToken == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: This node is not configured to support video uploads"))
		return
	}

	// Retrieve user public key and JWT from request body
	err := req.ParseMultipartForm(10 << 20)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Problem parsing multipart form data: %v", err))
		return
	}

	// Validate JWT
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
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Invalid token: %v", err))
		return
	}

	// Retrieve file from request
	file, header, err := req.FormFile("file")
	if err != nil {
		// handle the error
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideo: Error getting file: %v", err))
		return
	}
	defer file.Close()

	// Ensure file is less than 65MB
	if header.Size > 65*1024*1024 {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Files must be less than 250MB"))
		return
	}

	// Ensure file is a supported video type.
	contentType := header.Header.Get("Content-Type")
	if contentType != "video/quicktime" && contentType != "video/mp4" && contentType != "video/x-ms-wmv" {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideo: %v content type not supported", contentType))
		return
	}

	// Extract file information from file to determine how long the video file is.
	data, err := ffprobe.ProbeReader(context.Background(), file)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideo: Error probing file details: %v", err))
		return
	}

	// Ensure video is less than 2:30.
	if data.Format.DurationSeconds > 150 {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideo: File must be shorter than 2M 30S: %v", err))
		return
	}

	// Reset the file buffer.
	file.Seek(0, 0)

	// Construct request to retrieve upload URL from livepeer
	url := "https://livepeer.studio/api/asset/request-upload"
	client := &http.Client{}

	// Add name for uploaded file
	body := fmt.Sprintf(`{"name": "%s"}`, userPublicKey)

	// Create the request and set relevant headers
	request, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	// Set livepeer token
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %v", fes.Config.LivepeerToken))
	request.Header.Add("Tus-Resumable", "1.0.0")
	// Tells livepeer expected file size in bytes
	request.Header.Add("Upload-Length", req.Header.Get("Upload-Length"))
	request.Header.Set("Content-Type", "application/json")
	// Perform the request
	resp, err := client.Do(request)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideo: error performing POST request: %v", err))
		return
	}
	if resp.StatusCode != 200 {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: POST request did not return 201 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	// Read the uploadUrlResponse body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Error reading uploadUrlResponse body %v", err))
		return
	}

	// Unmarshal the uploadUrlResponse body into a struct
	var uploadUrlResponse LivepeerResponse
	err = json.Unmarshal(respBody, &uploadUrlResponse)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Error unmarshalling uploadUrlResponse body %v", err))
		return
	}

	// Upload the file to livepeer, using the URL requested above.
	uploadRequest, err := http.NewRequest("PUT", uploadUrlResponse.Url, file)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Error creating upload video request %v", err))
		return
	}

	uploadRequest.Header.Set("Content-Type", "video/mp4")

	client = &http.Client{}
	uploadResponse, err := client.Do(uploadRequest)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Error uploading video %v", err))
		return
	}
	defer uploadResponse.Body.Close()

	if err = json.NewEncoder(ww).Encode(uploadUrlResponse); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Problem encoding uploadUrlResponse as JSON: %v", err))
		return
	}
}

// UploadVideoOld creates a one-time tokenized URL that can be used to upload larger video files using the tus protocol.
// The client uses the Location header in the response from this function to upload the file.
// The client uses the Stream-Media-Id header in the response from cloudflare to understand how to access the file for streaming.
// See Cloudflare documentation here: https://developers.cloudflare.com/stream/uploading-videos/direct-creator-uploads#using-tus-recommended-for-videos-over-200mb
func (fes *APIServer) UploadVideoOld(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.CloudflareStreamToken == "" || fes.Config.CloudflareAccountId == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideoOld: This node is not configured to support video uploads"))
		return
	}
	uploadLengthStr := req.Header.Get("Upload-Length")
	if uploadLengthStr == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideoOld: Must provide Upload-Length header"))
		return
	}
	uploadLength, err := strconv.Atoi(uploadLengthStr)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideoOld: Unable to convert Upload-Length header to int for validation: %v", err))
		return
	}
	if uploadLength > 250*1024*1024 {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideo: Files must be less than 250MB"))
		return
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%v/stream?direct_user=true", fes.Config.CloudflareAccountId)
	client := &http.Client{}

	// Create the request and set relevant headers
	request, err := http.NewRequest("POST", url, nil)
	// Set Cloudflare token
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", fes.Config.CloudflareStreamToken))
	request.Header.Add("Tus-Resumable", "1.0.0")
	// Tells Cloudflare expected file size in bytes
	request.Header.Add("Upload-Length", req.Header.Get("Upload-Length"))
	// Upload-Metadata options are described here: https://developers.cloudflare.com/stream/uploading-videos/upload-video-file#supported-options-in-upload-metadata
	request.Header.Add("Upload-Metadata", req.Header.Get("Upload-Metadata"))
	// Perform the request
	resp, err := client.Do(request)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"UploadVideoOld: error performing POST request: %v", err))
		return
	}
	if resp.StatusCode != 201 {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideoOld: POST request did not return 201 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	// Allow Location and Stream-Media-Id headers so these headers can be used on the client size
	ww.Header().Add("Access-Control-Expose-Headers", "Location, Stream-Media-Id")
	// The Location header specifies the one-time tokenized URL
	ww.Header().Add("Location", resp.Header.Get("Location"))
	if ww.Header().Get("Access-Control-Allow-Origin") != "" {
		ww.Header().Set("Access-Control-Allow-Origin", "*")
	}
	if ww.Header().Get("Access-Control-Allow-Headers") != "*" {
		ww.Header().Set("Access-Control-Allow-Headers", "*")
	}
	ww.WriteHeader(200)
}

type CFVideoDetailsResponse struct {
	Result   map[string]interface{} `json:"result"`
	Success  bool                   `json:"success"`
	Errors   []interface{}          `json:"errors"`
	Messages []interface{}          `json:"messages"`
}

type GetVideoStatusResponseOld struct {
	ReadyToStream bool
	Duration      float64
	Dimensions    map[string]interface{}
}

func (fes *APIServer) GetVideoStatusOld(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.CloudflareStreamToken == "" || fes.Config.CloudflareAccountId == "" {
		_AddBadRequestError(ww, fmt.Sprintf("UploadVideoOld: This node is not configured to support video uploads"))
		return
	}
	vars := mux.Vars(req)
	videoId, videoIdExists := vars["videoId"]
	if !videoIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatusOld: Missing videoId"))
		return
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%v/stream/%v", fes.Config.CloudflareAccountId, videoId)
	client := &http.Client{}
	request, err := http.NewRequest("GET", url, nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", fes.Config.CloudflareStreamToken))
	request.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetVideoStatusOld: error performing GET request: %v", err))
		return
	}
	if resp.StatusCode != 200 {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatusOld: GET request did not return 200 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	cfVideoDetailsResponse := &CFVideoDetailsResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&cfVideoDetailsResponse); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatusOld: failed decoding body: %v", err))
		return
	}
	if err = resp.Body.Close(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatusOld: failed closing body: %v", err))
		return
	}
	isReady, _ := cfVideoDetailsResponse.Result["readyToStream"]
	duration, _ := cfVideoDetailsResponse.Result["duration"]
	dimensions, _ := cfVideoDetailsResponse.Result["input"]

	res := &GetVideoStatusResponseOld{
		ReadyToStream: isReady.(bool),
		Duration:      duration.(float64),
		Dimensions:    dimensions.(map[string]interface{}),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetVideoStatusOld: Problem serializing object to JSON: %v", err))
		return
	}
}

type LivepeerVideoDetailsResponse struct {
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type GetVideoStatusResponse struct {
	ReadyToStream bool
	Duration      float64
	Dimensions    map[string]interface{}
}

func (fes *APIServer) GetVideoStatus(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.LivepeerToken == "" {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: This node is not configured to support video uploads"))
		return
	}
	vars := mux.Vars(req)
	videoId, videoIdExists := vars["videoId"]
	if !videoIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: Missing videoId"))
		return
	}
	url := fmt.Sprintf("https://livepeer.studio/api/asset/%v", videoId)
	client := &http.Client{}
	request, err := http.NewRequest("GET", url, nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", fes.Config.LivepeerToken))
	request.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetVideoStatus: error performing GET request: %v", err))
		return
	}
	if resp.StatusCode != 200 {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: GET request did not return 200 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	livepeerVideoDetailsResponse := &LivepeerVideoDetailsResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&livepeerVideoDetailsResponse); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: failed decoding body: %v", err))
		return
	}
	if err = resp.Body.Close(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: failed closing body: %v", err))
		return
	}

	if err = json.NewEncoder(ww).Encode(livepeerVideoDetailsResponse); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetVideoStatus: Problem serializing object to JSON: %v", err))
		return
	}
}

type EnableVideoDownloadResponse struct {
	Default map[string]interface{}
}

// Cloudflare does NOT allow uploaded videos to be downloaded (just streamed)
// Cloudflare allows adding download support on a per-video basis
// EnableVideoDownload enables download support for an already uploaded video
// See Cloudflare documentation here: https://developers.cloudflare.com/stream/viewing-videos/download-videos/
func (fes *APIServer) EnableVideoDownload(ww http.ResponseWriter, req *http.Request) {
	if fes.Config.CloudflareStreamToken == "" || fes.Config.CloudflareAccountId == "" {
		_AddBadRequestError(ww, fmt.Sprintf("EnableVideoDownload: This node is not configured to support video uploads"))
		return
	}
	vars := mux.Vars(req)
	videoId, videoIdExists := vars["videoId"]
	if !videoIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("EnableVideoDownload: Missing videoId"))
		return
	}
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%v/stream/%v/downloads", fes.Config.CloudflareAccountId, videoId)
	client := &http.Client{}

	// This is a POST request because:
	// - If video downloading is not enabled for the video, the POST request will enable it and return the video URL
	// - If video downloading is already enabled for the video, the POST request will just return the video URL
	request, err := http.NewRequest("POST", url, nil)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", fes.Config.CloudflareStreamToken))
	request.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"EnableVideoDownload: error performing POST request: %v", err))
		return
	}
	if resp.StatusCode != 200 {
		_AddBadRequestError(ww, fmt.Sprintf("EnableVideoDownload: POST request did not return 200 status code but instead a status code of %v", resp.StatusCode))
		return
	}
	cfVideoDetailsResponse := &CFVideoDetailsResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&cfVideoDetailsResponse); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("EnableVideoDownload: failed decoding body: %v", err))
		return
	}
	if err = resp.Body.Close(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("EnableVideoDownload: failed closing body: %v", err))
		return
	}
	defaultVideo, _ := cfVideoDetailsResponse.Result["default"]

	res := &EnableVideoDownloadResponse{
		Default: defaultVideo.(map[string]interface{}),
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("EnableVideoDownload: Problem serializing object to JSON: %v", err))
		return
	}
}

type CFVideoOEmbedResponse struct {
	Height uint64 `json:"height"`
	Width  uint64 `json:"width"`
}

type GetVideoDimensionsResponse struct {
	Height uint64 `json:"height"`
	Width  uint64 `json:"width"`
}

func (fes *APIServer) GetVideoDimensions(ww http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	videoId, videoIdExists := vars["videoId"]
	if !videoIdExists {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: Missing videoId"))
		return
	}
	url := fmt.Sprintf("https://iframe.videodelivery.net/oembed?url=https://iframe.videodelivery.net/%v", videoId)
	client := &http.Client{}
	request, err := http.NewRequest("GET", url, nil)
	request.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(request)
	cfVideoOEmbedResponse := &CFVideoOEmbedResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&cfVideoOEmbedResponse); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: failed decoding body: %v", err))
		return
	}
	if err = resp.Body.Close(); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetVideoStatus: failed closing body: %v", err))
		return
	}

	res := &GetVideoDimensionsResponse{
		Height: cfVideoOEmbedResponse.Height,
		Width:  cfVideoOEmbedResponse.Width,
	}
	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddInternalServerError(ww, fmt.Sprintf("GetVideoStatus: Problem serializing object to JSON: %v", err))
		return
	}
}
