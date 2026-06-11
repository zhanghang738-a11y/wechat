# WechatDecrypt build package

This is a small GitHub Actions build package for HackerDev-Felix/WechatDecrypt.
It is intended to compile `dewechat.exe` online so the local PC does not need a
large Visual Studio or OpenSSL installation.

## Build with GitHub Actions

1. Create a new GitHub repository.
2. Upload all files in this directory to that repository.
3. Open the repository's `Actions` tab.
4. Run the `Build Windows executable` workflow.
5. Download the `dewechat-windows-x64` artifact.

Only source code is uploaded. Do not upload WeChat databases, keys, or personal
data to GitHub.

## Usage

Copy `dewechat.exe` and a copied database file into a separate test directory,
then run:

```powershell
.\dewechat.exe ChatMsg.db
```

The output file is named `dec_ChatMsg.db`. If that output already exists, the
program stops instead of appending or overwriting.

## Notes

- This project targets old Windows WeChat database encryption behavior.
- Newer WeChat versions may use different database files or encryption details.
- Always work on a copy of the database, not the original WeChat data directory.
- Use this only for data you own or are authorized to process.
