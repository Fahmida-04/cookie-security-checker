# Cookie Security Checker

A beginner-friendly cybersecurity web application that scans a website's cookies and evaluates their security configuration.

## Project Overview

Cookie Security Checker helps students and developers understand how HTTP cookies are configured and whether common cookie attributes are set. It analyzes cookies returned by a website and highlights potentially weaker configurations.

## Features

- Modern dark-themed dashboard
- URL validation and friendly error handling
- Scans HTTP cookies from a website response
- Checks Secure, HttpOnly, SameSite, Domain, Path, and expiration attributes
- Displays per-cookie risk and overall security score
- Beginner-friendly recommendations for improving cookie security
- Educational notice about ethical usage

## Technologies Used

- Python
- Flask
- Requests
- HTML
- CSS
- JavaScript

## Installation

1. Open VS Code and open the `cookie-security-checker` folder.
2. Create a Python virtual environment (recommended):

   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Run the Application

1. Start the Flask app:

   ```bash
   python app.py
   ```

2. Open the browser and go to `http://127.0.0.1:5000`.

## How Cookie Security Analysis Works

- The application sends an HTTP request to the website URL.
- It collects cookies from the response.
- It evaluates each cookie for the following attributes:
  - `Secure` — indicates whether the cookie is only sent over HTTPS.
  - `HttpOnly` — prevents JavaScript from reading the cookie in the browser.
  - `SameSite` — controls cross-site cookie sending behavior.
  - `Domain` and `Path` — define cookie scope.
  - `Expires` / `Max-Age` — indicate whether the cookie persists.
- The tool assigns risk points when attributes are missing or configured loosely.
- The score is calculated from 0 to 100 with a risk category.

## Example Results

- Secure cookies with HttpOnly and SameSite settings receive a better score.
- Cookies missing Secure or HttpOnly are shown as warnings.
- The dashboard shows total cookies analyzed, number of issues, and recommendations.

## Ethical Usage

This tool is intended for security testing and educational purposes. Only scan websites you own or have permission to test.

Do not use this tool for attacks, bypassing security controls, credential theft, or session hijacking.
