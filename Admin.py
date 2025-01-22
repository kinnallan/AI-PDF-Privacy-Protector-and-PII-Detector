# Required Library Imports
# Core Libraries
import streamlit as st  # Web application framework for creating interactive UI
import fitz  # PyMuPDF library for PDF processing
from PIL import Image  # Python Imaging Library for image processing
import os  # Operating system interface
import uuid  # Unique identifier generation
import bcrypt  # Password hashing
from datetime import datetime  # Date and time operations
import logging  # Logging functionality
from io import BytesIO  # In-memory binary stream operations
import tempfile  # Temporary file handling

# Firebase Libraries
import firebase_admin  # Firebase Admin SDK
from firebase_admin import credentials, storage, firestore  # Firebase services

# AI and NLP Libraries
from presidio_analyzer import AnalyzerEngine  # PII detection
from presidio_anonymizer import AnonymizerEngine  # PII anonymization
from transformers import pipeline, AutoModelForTokenClassification  # Hugging Face transformers
from transformers.models.auto.tokenization_auto import AutoTokenizer  # Tokenization
import spacy  # Advanced NLP processing
from collections import Counter  # Counting occurrences
import numpy as np  # Numerical operations

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIPDFMasker:
    def __init__(self):
        self.initialize_firebase()
        self.initialize_ai_models()

    def initialize_firebase(self):
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

    def initialize_ai_models(self):
        try:
            # Initialize Presidio Analyzer for PII detection
            self.analyzer = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()

            # Initialize transformer model for enhanced NER with error handling
            try:
                self.tokenizer = AutoTokenizer.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
                self.model = AutoModelForTokenClassification.from_pretrained("dbmdz/bert-large-cased-finetuned-conll03-english")
                self.ner_pipeline = pipeline("ner", model=self.model, tokenizer=self.tokenizer)
            except Exception as e:
                logger.warning(f"Failed to load transformer models: {str(e)}")
                # Fallback to simpler NER pipeline
                self.ner_pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")

            # Initialize spaCy with error handling
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

    def preprocess_text(self, text):
        doc = self.nlp(text)
        tokens = [token.text for token in doc]
        return " ".join(tokens)

    def detect_pii(self, text):
        processed_text = self.preprocess_text(text)
    
    # Define entities with their thresholds
        targeted_entities = {
            'PERSON': {'score_threshold': 0.85},
            'PHONE_NUMBER': {'score_threshold': 0.5},  # Lowered threshold for phone numbers
            'EMAIL_ADDRESS': {'score_threshold': 0.9},
            'CREDIT_CARD': {'score_threshold': 0.95},
            'US_SSN': {'score_threshold': 0.95},
            'AADHAAR': {'score_threshold': 0.95}
        }

    # Get Presidio analysis
        analyzer_results = self.analyzer.analyze(
            text=processed_text,
            language='en',
            return_decision_process=True,
            entities=list(targeted_entities.keys())
        )

        def is_aadhaar(text):
            cleaned = ''.join(filter(str.isdigit, text))
            return len(cleaned) == 12

        def is_phone_number(text):
            cleaned = ''.join(filter(str.isdigit, text))
            valid_lengths = [10, 11, 12]
        
            if len(cleaned) in valid_lengths:
                if len(cleaned) == 10 and cleaned[0] in '6789':
                    return True
                elif len(cleaned) in [11, 12] and cleaned.startswith(('91', '091')):
                    return cleaned[-10] in '6789'
            return False

        detected_pii = []
    
    # Process Presidio results
        for result in analyzer_results:
            if result.entity_type in targeted_entities:
                threshold = targeted_entities[result.entity_type]['score_threshold']
                if result.score >= threshold:
                    text_segment = processed_text[result.start:result.end]
                
                    should_add = True
                    if result.entity_type == 'PHONE_NUMBER':
                        should_add = is_phone_number(text_segment)
                    elif result.entity_type == 'AADHAAR':
                        should_add = is_aadhaar(text_segment)
                
                    if should_add:
                        detected_pii.append({
                            'text': text_segment,
                            'type': result.entity_type,
                            'confidence': float(result.score),
                            'span': (result.start, result.end)
                        })

    # Get additional results from NER pipeline
        ner_results = self.ner_pipeline(processed_text)
        for ner_result in ner_results:
            if ner_result['entity'] == 'PER' and ner_result['score'] > 0.85:
                detected_pii.append({
                    'text': ner_result['word'],
                    'type': 'PERSON',
                    'confidence': float(ner_result['score']),
                    'span': (ner_result['start'], ner_result['end'])
                })

    # Track name positions for duplicates
        name_positions = {}
        for pii in detected_pii:
            if pii['type'] == 'PERSON':
                if pii['text'] not in name_positions:
                    name_positions[pii['text']] = []
                name_positions[pii['text']].append(pii['span'])

    # Sort by position to maintain order
        detected_pii.sort(key=lambda x: x['span'][0])
        return detected_pii

    def apply_smart_blur(self, img, area, confidence, blur_radius=10):
        x0, y0, x1, y1 = [int(coord) for coord in area]
        
        # Create a more precise mask for the PII area
        mask = Image.new('L', img.size, 0)
        draw = ImageDraw.Draw(mask)
        
        # Calculate padding based on confidence
        padding = int(2 * (1 - confidence))  # Less padding for higher confidence
        draw.rectangle([
            max(0, x0 - padding),
            max(0, y0 - padding),
            min(img.width, x1 + padding),
            min(img.height, y1 + padding)
        ], fill=255)
        
        # Apply stronger blur for highly confident PII
        adjusted_radius = int(blur_radius * (0.5 + confidence/2))
        blurred = img.filter(ImageFilter.GaussianBlur(radius=adjusted_radius))
        
        # Create a smoother transition at the edges
        mask = mask.filter(ImageFilter.GaussianBlur(radius=1))
        
        img.paste(blurred, mask=mask)
        return img

    def upload_to_firebase(self, pdf_bytes, filename, doc_id):
        try:
            blob_path = f"pdfs/{doc_id}/{filename}"
            blob = self.bucket.blob(blob_path)

            blob.metadata = {'firebaseStorageDownloadTokens': str(uuid.uuid4())}

            blob.upload_from_string(
                pdf_bytes,
                content_type='application/pdf',
                timeout=300
            )

            blob.make_public()
            url = blob.generate_signed_url(
                version='v4',
                expiration=604800,
                method='GET'
            )

            logger.info(f"Successfully uploaded {filename}")
            return url

        except Exception as e:
            logger.error(f"Upload failed: {str(e)}")
            raise

    def process_pdf(self, pdf_bytes, original_filename, doc_id, owner_password, user_password, blur_radius=10):
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        original_pdf = BytesIO()
        blurred_pdf = BytesIO()
        detected_pii = []

        try:
            pdf_document.save(original_pdf)

            with tempfile.TemporaryDirectory() as temp_dir:
                for page_num in range(len(pdf_document)):
                    page = pdf_document[page_num]
                    text = page.get_text()

                    pii_results = self.detect_pii(text)

                    if pii_results:
                        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
                        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)

                        for pii in pii_results:
                            bbox = page.search_for(pii['text'])
                            if bbox:
                                scaled_bbox = [coord * 2 for coord in bbox[0]]
                                img = self.apply_smart_blur(img, scaled_bbox, pii['confidence'], blur_radius)

                                detected_pii.append({
                                    'page': page_num + 1,
                                    'type': pii['type'],
                                    'confidence': float(pii['confidence'])
                                })

                        temp_path = os.path.join(temp_dir, f"page_{page_num}.png")
                        img.save(temp_path, "PNG")
                        page.insert_image(page.rect, filename=temp_path)

                pdf_document.save(blurred_pdf)

            owner_password_hash = bcrypt.hashpw(owner_password.encode(), bcrypt.gensalt()).decode()
            user_password_hash = bcrypt.hashpw(user_password.encode(), bcrypt.gensalt()).decode()

            original_url = self.upload_to_firebase(
                original_pdf.getvalue(), 
                f"original_{original_filename}", 
                doc_id
            )
            blurred_url = self.upload_to_firebase(
                blurred_pdf.getvalue(), 
                f"blurred_{original_filename}", 
                doc_id
            )

            doc_ref = self.db.collection('documents').document(doc_id)
            doc_ref.set({
                'filename': original_filename,
                'owner_password': owner_password_hash,
                'user_password': user_password_hash,
                'original_url': original_url,
                'blurred_url': blurred_url,
                'detected_pii': detected_pii,
                'created_at': datetime.now(),
                'access_count': 0
            })

            return doc_id

        except Exception as e:
            logger.error(f"Error processing PDF: {str(e)}")
            raise
        finally:
            pdf_document.close()

def main():
    st.set_page_config(page_title="AI-Powered PDF PII Detector", layout="wide")
    st.title("AI-Powered PDF PII Detector and Masker")

    try:
        masker = AIPDFMasker()
        st.success("✅ Connected to Firebase and AI models successfully")
    except Exception as e:
        st.error(f"❌ Failed to initialize system: {str(e)}")
        st.stop()

    st.write("Upload a PDF to automatically detect and mask sensitive information using AI.")

    uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

    if uploaded_file:
        col1, col2 = st.columns(2)
        with col1:
            custom_doc_id = st.text_input("Enter Document ID", 
                                         help="Enter a unique identifier for your document")
            owner_password = st.text_input("Set Owner Password", type="password", 
                                          help="Password for accessing original content")
        with col2:
            user_password = st.text_input("Set User Password", type="password",
                                         help="Password for accessing protected content")

        blur_radius = st.slider("Blur Intensity", 5, 20, 10,
                               help="Adjust the blur effect intensity")

        if st.button("Process PDF"):
            if not custom_doc_id or not owner_password or not user_password:
                st.error("Please fill in all fields (Document ID and passwords)")
                return

            if owner_password == user_password:
                st.error("Owner and user passwords must be different")
                return

            try:
                with st.spinner("Processing PDF with AI models..."):
                    doc_id = masker.process_pdf(
                        uploaded_file.getvalue(),
                        uploaded_file.name,
                        custom_doc_id,
                        owner_password,
                        user_password,
                        blur_radius
                    )

                    # Fetch the document details to display PII information
                    doc_ref = masker.db.collection('documents').document(doc_id)
                    doc_data = doc_ref.get().to_dict()
                    
                    st.success("✅ PDF processed successfully with AI-powered PII detection!")
                    
                    # Display basic document info
                    st.info(f"Document ID: {doc_id}")
                    
                    # Create a detailed PII summary
                    if 'detected_pii' in doc_data and doc_data['detected_pii']:
                        st.subheader("📊 Detailed PII Detection Summary")
                        
                        # Count PII types
                        pii_counter = Counter(item['type'] for item in doc_data['detected_pii'])
                        
                        # Display summary in columns
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("#### 📑 PII Types Detected")
                            for pii_type, count in pii_counter.items():
                                st.write(f"- {pii_type}: {count} instances")
                        
                        with col2:
                            st.markdown("#### 📈 Detection Confidence")
                            for pii_type in pii_counter.keys():
                                confidences = [item['confidence'] for item in doc_data['detected_pii'] 
                                            if item['type'] == pii_type]
                                avg_confidence = sum(confidences) / len(confidences)
                                st.write(f"- {pii_type}: {avg_confidence:.2%} average confidence")
                        
                        # Display page-wise breakdown
                        st.markdown("#### 📄 Page-wise PII Distribution")
                        page_counter = Counter(item['page'] for item in doc_data['detected_pii'])
                        for page_num in sorted(page_counter.keys()):
                            st.write(f"Page {page_num}: {page_counter[page_num]} PII instances")
                            
                            # Show detailed breakdown per page
                            page_items = [item for item in doc_data['detected_pii'] if item['page'] == page_num]
                            with st.expander(f"View Details for Page {page_num}"):
                                for item in page_items:
                                    st.write(f"- Type: {item['type']}, Confidence: {item['confidence']:.2%}")
                    else:
                        st.info("No PII detected in the document.")

                    st.warning("""
                    Please save your Document ID and passwords to access the protected document.
                    The original and masked versions are now stored securely.
                    """)

            except Exception as e:
                st.error(f"❌ Error processing PDF: {str(e)}")

if __name__ == "__main__":
    main()
