Response bodies for `SdkRecordedResponseTest`, one per endpoint, in the shape the staging server
emits them: every field the server writes, including the ones the plugin never reads. They were
taken from the handlers on `platform` origin/staging (the v3 API and the auth service) and, for the
deprecated `/v2/config` and `/v2/search/binaries`, from `reai-api`.

When an endpoint's response changes, refresh its file from a live staging response.
