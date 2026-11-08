# Phishing-URL-Detection-System

A Python and Flask-based web application that analyzes URLs for potentially suspicious characteristics and provides website verification details.

Features
* URL Analysis: Examines URL structure, suspicious keywords, IP addresses, HTTPS usage, and other characteristics.
* Risk Scoring: Assigns a risk score and categorizes URLs into low, medium, and high risk levels.
* Live Website Verification: Checks DNS resolution and website accessibility.
* HTTP Analysis: Displays HTTP status codes, response time, and redirect information.
* Lookalike Domain Detection: Identifies potentially suspicious domains using similarity checks.
* URL Breakdown: Displays important URL components and analysis results.
* Scan History: Maintains a history of previously analyzed URLs.

Technologies Used
* Python
* Flask
* HTML
* CSS
* JavaScript
* Requests Library

Project Structure

Phishing-URL-Detection-System/
│
├── app.py
├── detector.py
├── website_checker.py
├── lookalike_detector.py
├── requirements.txt
│
├── static/
│   ├── style.css
│   └── script.js
│
└── templates/
    └── index.html

Installation and Setup

1. Clone the Repository

git clone https://github.com/bhanuu07/Phishing-URL-Detection-System.git

2. Navigate to the Project Directory

cd Phishing-URL-Detection-System

3. Create a Virtual Environment

python -m venv venv

4. Activate the Virtual Environment

Windows:

venv\Scripts\activate

macOS / Linux:

source venv/bin/activate

5. Install Dependencies

pip install -r requirements.txt

6. Run the Application

python app.py

Open your browser and visit:

http://127.0.0.1:5000

Disclaimer

This project is an educational prototype intended for URL analysis and security awareness. Its risk scores are heuristic indicators and should not be treated as definitive proof that a website is safe or malicious.

Development Note

AI tools were used as assistance during implementation. This project is intended for educational purposes and further development.
