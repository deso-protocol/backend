![DeSo Logo](assets/camelcase_logo.svg)

# About DeSo

DeSo is a blockchain built from the ground up to support a fully-featured
social network. Its architecture is similar to Bitcoin, only it supports complex
social network data like profiles, posts, follows, creator coin transactions, and
more.

[Read about the vision](https://docs.deso.org/the-vision)

# About This Repo

Documentation for this repo lives on docs.deso.org. Specifically, the following
docs should give you everything you need to get started:

- [DeSo Code Walkthrough](https://docs.deso.org/code/walkthrough)
- [Setting Up Your Dev Environment](https://docs.deso.org/code/dev-setup)
- [Making Your First Changes](https://docs.deso.org/code/making-your-first-changes)

# Common Errors and their solutions

These are common errors you may encounter in getting `./n0_test` to succeed.

_If you encounter an error not mentioned here in setting up your installation, please share the solution here with the community_

### no `pkg-config`

#### Error

```
# pkg-config --cflags  -- vips vips vips vips
pkg-config: exec: "pkg-config": executable file not found in $PATH
```

#### Solution

```
brew install pkg-config
```

### no `vips`

#### Error

```
# pkg-config --cflags  -- vips vips vips vips
Package vips was not found in the pkg-config search path.
Perhaps you should add the directory containing `vips.pc'
to the PKG_CONFIG_PATH environment variable
No package 'vips' found

```

#### Solution

```
brew install vips
```

### invalig `pkg-config` flag

#### Error

```
go build github.com/h2non/bimg: invalid flag in pkg-config --cflags: -Xpreprocessor
```

#### Solution

```
export CGO_CFLAGS_ALLOW="-Xpreprocessor"
```
