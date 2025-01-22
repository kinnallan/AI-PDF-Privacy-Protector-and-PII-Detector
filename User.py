# Importing necessary libraries
import streamlit as st  # Streamlit for creating the web interface
import firebase_admin  # Firebase Admin SDK for interacting with Firebase services
from firebase_admin import credentials, storage, firestore  # Modules for Firebase credentials, storage, and Firestore database
import os  # OS for file and path handling
import bcrypt  # Bcrypt for secure password hashing and verification
import logging  # Logging for tracking and debugging

# Setting up logging for debugging and tracking
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)  # Logger instance for this file

# Defining a class to handle accessing AI-protected PDFs
class AIPDFAccessor:
    def __init__(self):
        # Initialize Firebase when an instance of this class is created
        self.initialize_firebase()

    def initialize_firebase(self):
        """
        Initializes Firebase Admin SDK. Connects to the Firestore database
        and the Firebase Storage bucket.
        """
        try:
            # Check if Firebase is already initialized
            if not firebase_admin._apps:
                # Get the directory of this script
                current_dir = os.path.dirname(os.path.abspath(__file__))
                
                # Path to Firebase credentials JSON file
                cred_path = os.path.join(current_dir, "pdfblur-firebase-adminsdk-dfic3-3bebd41ba0.json")
                
                # Raise an error if the credentials file is missing
                if not os.path.exists(cred_path):
                    raise FileNotFoundError(f"Firebase credentials file not found at {cred_path}")
                
                # Initialize Firebase with the credentials
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred, {
                    'storageBucket': 'pdfblur.firebasestorage.app'
                })
                
            # Initialize Firestore database client
            self.db = firestore.client()
            logger.info("✅ Firebase initialized successfully")
            
        except Exception as e:
            # Log and re-raise any error that occurs during Firebase initialization
            logger.error(f"Firebase initialization failed: {str(e)}")
            raise

    def verify_access(self, doc_id, password):
        """
        Verifies access to a document using its ID and password.

        Args:
            doc_id (str): Unique document ID.
            password (str): Password provided by the user.

        Returns:
            tuple: Filename, URL, detected PII information, and access type.
        """
        try:
            # Reference to the document in Firestore
            doc_ref = self.db.collection('documents').document(doc_id)
            doc = doc_ref.get()  # Retrieve the document
            
            # If the document does not exist, log a warning and return an error
            if not doc.exists:
                logger.warning(f"Document {doc_id} not found")
                return None, None, None, "Document not found"

            # Fetch document data
            doc_data = doc.to_dict()
            
            # Check if the provided password matches the owner password
            if bcrypt.checkpw(password.encode(), doc_data['owner_password'].encode()):
                logger.info(f"Owner access granted for {doc_id}")
                # Increment access count in Firestore
                doc_ref.update({'access_count': doc_data.get('access_count', 0) + 1})
                return doc_data['filename'], doc_data['original_url'], doc_data.get('detected_pii', []), "owner"
            
            # Check if the provided password matches the user password
            if bcrypt.checkpw(password.encode(), doc_data['user_password'].encode()):
                logger.info(f"User access granted for {doc_id}")
                # Increment access count in Firestore
                doc_ref.update({'access_count': doc_data.get('access_count', 0) + 1})
                return doc_data['filename'], doc_data['blurred_url'], doc_data.get('detected_pii', []), "user"
            
            # If neither password matches, log a warning and return an error
            logger.warning(f"Invalid password attempt for {doc_id}")
            return None, None, None, "Invalid password"
            
        except Exception as e:
            # Log and re-raise any error that occurs during verification
            logger.error(f"Error verifying access: {str(e)}")
            raise

# Main function for the Streamlit interface
def main():
    # Set page title and layout
    st.set_page_config(page_title="AI-Protected PDF Access", layout="wide")
    st.title("Access AI-Protected PDF Document")  # Title displayed on the app
    
    try:
        # Initialize the AIPDFAccessor instance
        accessor = AIPDFAccessor()
        st.success("✅ Connected to Firebase successfully")  # Show success message
    except Exception as e:
        # Show error message and stop execution if initialization fails
        st.error(f"❌ Failed to connect to Firebase: {str(e)}")
        st.stop()
    
    # Instructions for the user
    st.write("Access your AI-protected PDF document using your Document ID and password.")
    
    # Input fields for document ID and password
    doc_id = st.text_input("Document ID")
    password = st.text_input("Password", type="password")
    
    # Button to access the document
    if st.button("Access Document"):
        if not doc_id or not password:
            # Error if any input field is empty
            st.error("Please enter both Document ID and password")
            return
        
        try:
            # Verify access using the accessor class
            filename, url, pii_info, access_type = accessor.verify_access(doc_id, password)
            
            if url:  # If access is granted
                st.success(f"✅ Access granted as {access_type}")
                st.write(f"Document: {filename}")
                
                # Display AI-detected PII summary if available
                if pii_info and len(pii_info) > 0:
                    st.subheader("AI-Detected Sensitive Information Summary")
                    pii_types = set(item['type'] for item in pii_info)
                    st.write("Types of sensitive information protected by AI:")
                    
                    # Display stats in two columns
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Protected Information Types:**")
                        for pii_type in pii_types:
                            count = len([item for item in pii_info if item['type'] == pii_type])
                            st.write(f"- {pii_type}: {count} instances")
                    
                    with col2:
                        # Calculate and display detection stats
                        avg_confidence = sum(item['confidence'] for item in pii_info) / len(pii_info)
                        st.write("**Detection Statistics:**")
                        st.write(f"- Total items protected: {len(pii_info)}")
                        st.write(f"- AI confidence level: {avg_confidence:.2%}")
                        st.write(f"- Pages with protected content: {len(set(item['page'] for item in pii_info))}")
                
                # Provide access link to the document
                st.markdown("### Document Access")
                if access_type == "owner":
                    st.info("""
                    🔓 You have full access to the original document.
                    All sensitive information is visible as you have owner privileges.
                    """)
                else:
                    st.info("""
                    🔒 You have access to the AI-protected version.
                    Sensitive information has been automatically detected and masked.
                    """)
                
                # Document preview/download section
                st.markdown("### Document Preview & Download")
                st.markdown(f"[Click here to view/download PDF]({url})")
                
                # Additional user instructions
                if access_type == "user":
                    st.write("""
                    ℹ️ **Note on Protected Content:**
                    - The AI system has automatically identified and masked sensitive information
                    - Masked areas indicate presence of personal, financial, or confidential data
                    - Contact the document owner if you need access to the original content
                    """)
                
                # Usage tips in the sidebar
                st.sidebar.markdown("### Usage Tips")
                st.sidebar.write("""
                - Keep your Document ID and password secure
                - Don't share access credentials with others
                - Use the protected version for general sharing
                - Contact support if you encounter any issues
                """)
                
            else:  # If access is denied
                st.error(f"❌ Access denied: {access_type}")
                if access_type == "Document not found":
                    st.write("Please check your Document ID and try again.")
                elif access_type == "Invalid password":
                    st.write("Please check your password and try again.")
        
        except Exception as e:
            # Log and display any error that occurs
            st.error(f"❌ Error accessing document: {str(e)}")
            logger.error(f"Access error: {str(e)}")

# Run the Streamlit app
if __name__ == "__main__":
    main()
