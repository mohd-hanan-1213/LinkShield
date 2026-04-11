# LinkShield

Chrome extension that safeguards risk URLs by analyzing the link structure and searching for their past reputations

## Current flow

- Score `< 30`: open directly
- Score `30-69`: ask the backend to verify the URL with VirusTotal
- Score `>= 70`: redirect to the warning page immediately
- VirusTotal safe results are cached in the extension for 24 hours to avoid repeated scans

## Local setup

1. Copy `.env.example` to `.env`
2. Put your VirusTotal key in `VT_API_KEY`
3. For production, set `ALLOWED_ORIGIN` to your extension origin instead of `*`
4. Run `npm install` to install dependencies
5. Start the backend with `npm start`
6. Reload the extension in Chrome

## Security note

Do not commit `.env` or hardcode your VirusTotal key in the extension. The key should stay on the backend only.
