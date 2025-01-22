# Web Application Framework
import streamlit as st  # Creates the web interface for the application

# PDF Processing
import fitz  # PyMuPDF library for reading and manipulating PDF files

# Image Processing
from PIL import Image  # Pillow library for image manipulation
from PIL import ImageDraw, ImageFilter  # Additional Pillow modules for drawing and applying filters

# Firebase Integration
import firebase_admin  # Base Firebase admin SDK
from firebase_admin import credentials  # Handles Firebase authentication
from firebase_admin import storage  # Manages Firebase cloud storage
from firebase_admin import firestore  # Handles Firebase database operations

# Utility Libraries
import uuid  # Generates unique identifiers
import bcrypt  # Handles password hashing and security
from datetime import datetime  # Manages dates and times
import logging  # Provides logging capabilities
import os  # Handles operating system operations
from io import BytesIO  # Manages binary I/O operations
import tempfile  # Creates temporary files and directories
from collections import Counter  # Provides counter objects for counting items

# AI and NLP Libraries
from presidio_analyzer import AnalyzerEngine  # Microsoft's PII detection engine
from presidio_anonymizer import AnonymizerEngine  # Microsoft's PII anonymization engine
from transformers import pipeline  # Hugging Face's main interface for NLP tasks
from transformers import AutoModelForTokenClassification  # Loads pre-trained NLP models
from transformers.models.auto.tokenization_auto import AutoTokenizer  # Handles text tokenization
import numpy as np  # Numerical operations library
import spacy  # Advanced NLP library for text processing

# Logging Configuration

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Main Application Class

class AIPDFMasker:
    """
    Main class that handles PDF processing, PII detection, and document masking.
    Combines multiple AI models for enhanced PII detection accuracy.
    """
    def __init__(self):
        self.initialize_firebase()
        self.initialize_ai_models()

    # Firebase Initialization

    def initialize_firebase(self):
        """
        Sets up Firebase connection for document storage and retrieval.
        - Loads credentials from local JSON file
        - Initializes Firebase app if not already initialized
        - Sets up Firestore database and storage bucket connections
        """
        try:
            if not firebase_admin._apps:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                cred_path = os.path.join(current_dir, "pdfblur-firebase-adminsdk-dfic3-3bebd41ba0.json")

                if not os.path.exists(cred_path):
                    raise FileNotFoundError(f"Firebase credentials file not found at {cred_path}")

                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': 'pdfblur.firebasestorage.app'
                })

            self.db = firestore.client()
            self.bucket = storage.bucket()
            logger.info("✅ Firebase initialized successfully")

        except Exception as e:
            logger.error(f"Firebase initialization failed: {str(e)}")
            raise

    # AI Models Initialization

    def initialize_ai_models(self):
        """
        Initializes multiple AI models for PII detection:
        1. Presidio Analyzer: Primary PII detection engine
        2. BERT Model: Enhanced named entity recognition
        3. SpaCy Model: Text preprocessing and additional NER
        Includes fallback mechanisms for model loading failures
        """
        try:
            # Initialize Presidio for PII detection
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()

            # Set up BERT model with fallback option
            try:
                self.tokenizer = AutoTokenizer.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
                self.model = AutoModelForTokenClassification.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
                self.ner_pipeline = pipeline("ner", model=self.model, tokenizer=self.tokenizer)
            except Exception as e:
                logger.warning(f"Failed to load transformer models: {str(e)}")
                self.ner_pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")

            # Initialize spaCy with automatic download if needed
            try:
                self.nlp = spacy.load('en_core_web_trf')
            except OSError:
                logger.info("Downloading spaCy model...")
                os.system('python -m spacy download en_core_web_trf')
                self.nlp = spacy.load('en_core_web_trf')

            logger.info("✅ AI models initialized successfully")
        except Exception as e:
            logger.error(f"AI models initialization failed: {str(e)}")
            raise

    # Text Processing Methods

    def preprocess_text(self, text):
        """
        Preprocesses text using spaCy for improved PII detection:
        - Tokenizes text
        - Handles special characters
        - Prepares text for NER processing
        """
        doc = self.nlp(text)
        tokens = [token.text for token in doc]
        return " ".join(tokens)

    # PII Detection Logic

    def detect_pii(self, text):
        """
        Comprehensive PII detection using multiple models:
        - Uses Presidio for standard PII (emails, phone numbers, etc.)
        - Uses BERT-NER for enhanced person name detection
        - Implements custom validation for specific PII types
        
        Parameters:
            text (str): Input text to analyze for PII
            
        Returns:
            list: Detected PII items with positions and confidence scores
        """
        processed_text = self.preprocess_text(text)
    
        # Define detection thresholds for different PII types
        targeted_entities = {
            'PERSON': {'score_threshold': 0.85},
            'PHONE_NUMBER': {'score_threshold': 0.5},
            'EMAIL_ADDRESS': {'score_threshold': 0.9},
            'CREDIT_CARD': {'score_threshold': 0.95},
            'US_SSN': {'score_threshold': 0.95},
            'AADHAAR': {'score_threshold': 0.95}
        }

    # Image Processing Methods

    def apply_smart_blur(self, img, area, confidence, blur_radius=10):
        """
        Applies intelligent blurring to detected PII areas:
        - Adjusts blur intensity based on confidence
        - Creates smooth edge transitions
        - Adds dynamic padding
        
        Parameters:
            img (PIL.Image): Source image
            area (tuple): Coordinates to blur (x0, y0, x1, y1)
            confidence (float): Detection confidence score
            blur_radius (int): Base blur intensity
        
        Returns:
            PIL.Image: Processed image with applied blur
        """
        x0, y0, x1, y1 = [int(coord) for coord in area]
        
        # Create mask for precise blurring
        mask = Image.new('L', img.size, 0)
        draw = ImageDraw.Draw(mask)
        
        # Add dynamic padding based on confidence
        padding = int(2 * (1 - confidence))
        draw.rectangle([
            max(0, x0 - padding),
            max(0, y0 - padding),
            min(img.width, x1 + padding),
            min(img.height, y1 + padding)
        ], fill=255)
        
        # Adjust blur strength based on confidence
        adjusted_radius = int(blur_radius * (0.5 + confidence/2))
        blurred = img.filter(ImageFilter.GaussianBlur(radius=adjusted_radius))
        
        # Smooth edges
        mask = mask.filter(ImageFilter.GaussianBlur(radius=1))
        
        img.paste(blurred, mask=mask)
        return img

# Streamlit Web Interface

def main():
    """
    Sets up the Streamlit web interface with:
    - File upload capability
    - Password protection settings
    - Blur intensity control
    - PII detection results display
    - Error handling and user feedback
    """
    st.set_page_config(page_title="AI-Powered PDF PII Detector", layout="wide")
    st.title("AI-Powered PDF PII Detector and Masker")
  

if __name__ == "__main__":
    main()
