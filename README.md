<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/638b3a52-aeb4-4f11-8ce9-816570c1e79c

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Copy `.env.example` to `.env` and set your secrets locally:
   `cp .env.example .env`
3. Run the app:
   `npm run dev`

## Deploy to GitHub Pages

This repository includes a GitHub Actions workflow to deploy the site automatically on push to `main`.

1. Add the required secrets in your GitHub repository settings:
   - `GEMINI_API_KEY`
   - `VITE_EMAILJS_SERVICE_ID`
   - `VITE_EMAILJS_TEMPLATE_ID`
   - `VITE_EMAILJS_PUBLIC_KEY`
   - `APP_URL` (optional; set to your public site URL if needed)
   - `VITE_BASE_URL` (optional; for repo pages use `/Sentinel/`)
2. Commit and push to `main`:
   `git add . && git commit -m "Prepare site for GitHub Pages deployment" && git push origin main`
3. The workflow will build the app and publish `dist/` to the `gh-pages` branch.
4. In GitHub Pages settings, choose `gh-pages` as the source if it is not automatically selected.

> Keep `.env` local and do not commit it. Use `.env.example` as the tracked template.
