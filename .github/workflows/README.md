# Workflows

## build

What docker tags will be produced and when?  It depends on the trigger.  

Doc: https://github.com/docker/metadata-action#basic (the following is a summary of the doc)

| Event           | Ref                           | Docker Tags                         |
|-----------------|-------------------------------|-------------------------------------|
| `pull_request`  | `refs/pull/2/merge`           | `pr-2`                              |
| `push`          | `refs/heads/main`             | `main`                              |
| `push`          | `refs/heads/releases/v1`      | `releases-v1`                       |
| `push tag`      | `refs/tags/v1.2.3`            | `v1.2.3`, `latest`                  |
| `push tag`      | `refs/tags/v2.0.8-beta.67`    | `v2.0.8-beta.67`, `latest`          |

### Open a pull request
Opening a pull request will create a docker container with a tag named after the PR #

### Pushing a tag:

Create the tag:
```
git tag -a v1.4.2 -m "my version 1.4.2"
```

Push the tag to the repository:
```
git push origin v1.4.2
```

This will create these tags for the container:
* v1.4.2
* latest

## Deploy
On tag, the deployment will run.

Based on semver: `major.minor.patch`

| Changes         | Deploy to              | 
|-----------------|------------------------|
| `patch`         | `dev`                  |
| `minor`         | `staging`              |
| `major`         | `production`           |


## Performing a release from dev to prod

v1.1.1
* Git push tag v1.1.1 manually
* docker container build
* deploy to dev
* test dev
* everything is good

Promote v1.1.1 to staging
* Change the staging's docker image tag to this manually?
* Open PR
* deploy to staging
* test staging
* everything is good

Promote v1.1.1 to prod
* Change the prod's docker image tag to this manually?
* Ope PR
* Deploy to prod
* test prod
* everything is good



