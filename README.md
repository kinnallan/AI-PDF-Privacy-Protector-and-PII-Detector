# AI-PDF-Privacy-Protector-and-PII-Detector
An advanced AI-powered application that automatically detects and masks Personally Identifiable Information (PII) in PDF documents while maintaining document integrity and providing secure access control.

# Features

AI-Powered PII Detection: Automatically identifies sensitive information including:

Personal names

Phone numbers

Email addresses

Credit card numbers

Social Security numbers

Aadhaar numbers (Indian national ID)


#Smart Document Protection:

Intelligent blurring with confidence-based intensity

Maintains document structure and readability

Selective masking of only sensitive information


# Secure Access Control:

Dual-level access system (owner/user)

Password-protected document access

Encrypted storage and transmission


# Advanced AI Models:

Uses Presidio Analyzer for PII detection

BERT-based Named Entity Recognition

SpaCy natural language processing

Multiple AI model fallback system


# Technical Stack

Frontend: Streamlit

Backend: Python

AI/ML:

Presidio Analyzer & Anonymizer |
Hugging Face Transformers |
SpaCy NLP


Storage: Firebase Storage

Database: Firebase Firestore

PDF Processing: PyMuPDF (fitz)

# Project Structure

AI-PDF-Privacy-Protector/

│   ├── __init__.py

│   ├── admin.py           # Main processing script / admin side UI

│   └── user.py         # Document access control / User side UI

└── requirements.txt

# requirements.txt

streamlit>=1.8.0

firebase-admin>=5.0.0

PyMuPDF>=1.18.0

presidio-analyzer>=2.2.0

presidio-anonymizer>=2.2.0

transformers>=4.18.0

spacy>=3.2.0

Pillow>=9.0.0

bcrypt>=3.2.0

python-dotenv>=0.19.0

numpy>=1.21.0

pandas>=1.3.0

# Installation 

1. Install dependencies:

   bash - pip install -r requirements.txt

2. Download SpaCy model:

   python -m spacy download en_core_web_trf

3. Set up Firebase:

Create a Firebase project

Download your Firebase admin SDK JSON file

Rename it to pdfblur-firebase-adminsdk-dfic3-3bebd41ba0.json

Place it in the project root directory

Note : The Firebase credentials JSON file (pdfblur-firebase-adminsdk-dfic3-3bebd41ba0.json) is not included in this repository for security reasons. Generate your own service account credentials JSON file. Place it in the project root directory with the name pdfblur-firebase-adminsdk-dfic3-3bebd41ba0.json. Without this file, you won't be able to access Firebase services.

# Usage 

1. Start the processing application:

bash - streamlit run admin.py

2. Start the access application:

bash - streamlit run user.py

3. Admin side UI - Upload a PDF and set access credentials:

Enter a unique Document ID

Set owner password (for original document)

Set user password (for protected document)

Adjust blur intensity if needed

4. User Side UI - Access protected documents:

Use Document ID and appropriate password

Owner password provides access to original document

User password provides access to protected version

# Conclusion

The AI PDF Privacy Protector and PII Detector represents a significant step forward in document security and privacy protection. By combining advanced AI technologies with robust security measures, this tool offers:

Intelligent Protection: Leverages multiple AI models to provide accurate PII detection and protection while maintaining document usability.

Flexible Access Control: Enables organizations to safely share documents while maintaining control over sensitive information.

Scalable Solution: Suitable for both individual users and organizations handling sensitive documents.

Compliance Support: Helps organizations meet privacy regulations by automatically identifying and protecting sensitive information.

Whether you're a business handling customer data, a healthcare provider managing patient records, or an organization dealing with confidential documents, this tool provides the necessary features to ensure document privacy while maintaining accessibility.


#Future Development

The project is open to contributions and improvements, particularly in areas such as:

Additional PII detection capabilities

Enhanced AI model accuracy

Support for more document formats

Advanced encryption features

User interface improvements

