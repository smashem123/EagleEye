"""
NLP Pipeline for advanced text processing and machine learning
Real-time scam detection with sentiment analysis and entity extraction
"""
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import json
from pathlib import Path

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import spacy
    from spacy import displacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False


class NLPPipeline:
    """Advanced NLP pipeline for scam detection"""
    
    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or Path.home() / ".eagleeye" / "models"
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.nlp = None
        self.classifier = None
        self.vectorizer = None
        
        # Initialize models
        self._init_spacy()
        self._init_ml_models()
        
        # Scam training data (basic examples)
        self.training_data = self._get_training_data()
    
    def _init_spacy(self):
        """Initialize spaCy NLP model"""
        if SPACY_AVAILABLE:
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                # Try to download the model
                try:
                    spacy.cli.download("en_core_web_sm")
                    self.nlp = spacy.load("en_core_web_sm")
                except:
                    self.nlp = None
    
    def _init_ml_models(self):
        """Initialize machine learning models"""
        if not SKLEARN_AVAILABLE:
            return
        
        # Try to load existing model
        model_file = self.model_path / "scam_classifier.joblib"
        vectorizer_file = self.model_path / "tfidf_vectorizer.joblib"
        
        if model_file.exists() and vectorizer_file.exists():
            try:
                self.classifier = joblib.load(model_file)
                self.vectorizer = joblib.load(vectorizer_file)
                return
            except:
                pass
        
        # Train new model if not available
        self._train_classifier()
    
    def _get_training_data(self) -> List[Tuple[str, str]]:
        """Get training data for scam classification"""
        return [
            # Phishing examples
            ("Urgent: Your account will be suspended. Click here to verify immediately.", "phishing"),
            ("Security Alert: Suspicious activity detected. Confirm your identity now.", "phishing"),
            ("Your payment failed. Update your billing information to avoid service interruption.", "phishing"),
            ("Verify your account within 24 hours or it will be permanently closed.", "phishing"),
            ("Important: Your bank account has been compromised. Call us immediately.", "phishing"),
            
            # Tech support scams
            ("Warning: Your computer is infected with malware. Call Microsoft Support now.", "tech_support"),
            ("Virus detected on your system. Download our security software immediately.", "tech_support"),
            ("Your Windows license has expired. Contact support to renew.", "tech_support"),
            ("Critical security alert: Your system is at risk. Call this number for help.", "tech_support"),
            
            # Romance scams
            ("My dearest love, I need your help to transfer my inheritance money.", "romance"),
            ("You are my soulmate. I'm stuck in another country and need financial help.", "romance"),
            ("I love you so much. Can you send me money for my plane ticket to see you?", "romance"),
            ("My heart belongs to you. I need help with customs fees to send you a gift.", "romance"),
            
            # Investment scams
            ("Guaranteed 500% return on your investment in just 30 days!", "investment"),
            ("Make $5000 per week working from home with our proven system.", "investment"),
            ("Exclusive cryptocurrency opportunity - double your money in 24 hours.", "investment"),
            ("Risk-free forex trading with guaranteed profits. Join now!", "investment"),
            
            # Lottery scams
            ("Congratulations! You've won $1,000,000 in our international lottery.", "lottery"),
            ("You are the lucky winner of our sweepstakes. Claim your prize now!", "lottery"),
            ("Your email has been selected for our cash prize. Send processing fee.", "lottery"),
            
            # Legitimate examples
            ("Thank you for your purchase. Your order will be shipped within 2 business days.", "legitimate"),
            ("Your monthly statement is now available. Log in to view your account.", "legitimate"),
            ("Welcome to our newsletter. You can unsubscribe at any time.", "legitimate"),
            ("Your appointment is confirmed for tomorrow at 2 PM.", "legitimate"),
            ("Password reset requested. Click here if this was you.", "legitimate"),
            ("Your subscription expires in 7 days. Renew to continue service.", "legitimate"),
        ]
    
    def _train_classifier(self):
        """Train the scam classification model"""
        if not SKLEARN_AVAILABLE:
            return
        
        texts, labels = zip(*self.training_data)
        
        # Create pipeline with TF-IDF and Naive Bayes
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words='english',
            ngram_range=(1, 2),
            lowercase=True
        )
        
        self.classifier = Pipeline([
            ('tfidf', self.vectorizer),
            ('nb', MultinomialNB(alpha=0.1))
        ])
        
        # Train the model
        self.classifier.fit(texts, labels)
        
        # Save the trained model
        try:
            joblib.dump(self.classifier, self.model_path / "scam_classifier.joblib")
            joblib.dump(self.vectorizer, self.model_path / "tfidf_vectorizer.joblib")
        except:
            pass  # Continue without saving if there's an issue
    
    async def classify_text(self, text: str) -> Dict[str, Any]:
        """Classify text using machine learning model"""
        if not self.classifier:
            return {
                'predicted_class': 'unknown',
                'confidence': 0.0,
                'probabilities': {}
            }
        
        try:
            # Predict class
            prediction = self.classifier.predict([text])[0]
            
            # Get probabilities
            probabilities = self.classifier.predict_proba([text])[0]
            classes = self.classifier.classes_
            
            prob_dict = dict(zip(classes, probabilities))
            confidence = max(probabilities)
            
            return {
                'predicted_class': prediction,
                'confidence': float(confidence),
                'probabilities': {k: float(v) for k, v in prob_dict.items()}
            }
        except:
            return {
                'predicted_class': 'unknown',
                'confidence': 0.0,
                'probabilities': {}
            }
    
    async def extract_advanced_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extract entities using spaCy NLP"""
        entities = []
        
        if not self.nlp:
            return entities
        
        try:
            doc = self.nlp(text)
            
            for ent in doc.ents:
                entities.append({
                    'text': ent.text,
                    'label': ent.label_,
                    'description': spacy.explain(ent.label_),
                    'start': ent.start_char,
                    'end': ent.end_char,
                    'confidence': 0.8
                })
            
            # Extract custom financial entities
            financial_patterns = [
                (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'CREDIT_CARD'),
                (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
                (r'\b\d{9,12}\b', 'ACCOUNT_NUMBER'),
                (r'\$[\d,]+(?:\.\d{2})?', 'MONEY'),
                (r'\b\d{3}-\d{3}-\d{4}\b', 'PHONE'),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL')
            ]
            
            for pattern, label in financial_patterns:
                matches = re.finditer(pattern, text)
                for match in matches:
                    entities.append({
                        'text': match.group(),
                        'label': label,
                        'description': f'Financial identifier: {label}',
                        'start': match.start(),
                        'end': match.end(),
                        'confidence': 0.9
                    })
        
        except Exception as e:
            # Return empty list if processing fails
            pass
        
        return entities
    
    async def analyze_sentiment_advanced(self, text: str) -> Dict[str, Any]:
        """Advanced sentiment analysis"""
        if not self.nlp:
            return {
                'polarity': 0.0,
                'subjectivity': 0.0,
                'emotion': 'neutral'
            }
        
        try:
            doc = self.nlp(text)
            
            # Basic sentiment indicators
            positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic']
            negative_words = ['bad', 'terrible', 'awful', 'horrible', 'urgent', 'critical', 'warning']
            
            pos_count = sum(1 for token in doc if token.text.lower() in positive_words)
            neg_count = sum(1 for token in doc if token.text.lower() in negative_words)
            
            total_words = len([token for token in doc if not token.is_stop and not token.is_punct])
            
            if total_words == 0:
                polarity = 0.0
            else:
                polarity = (pos_count - neg_count) / total_words
            
            # Determine emotion
            emotion = 'neutral'
            if polarity > 0.1:
                emotion = 'positive'
            elif polarity < -0.1:
                emotion = 'negative'
            
            # Check for urgency/fear
            urgency_words = ['urgent', 'immediate', 'now', 'quickly', 'asap', 'emergency']
            urgency_score = sum(1 for token in doc if token.text.lower() in urgency_words) / max(total_words, 1)
            
            if urgency_score > 0.05:
                emotion = 'urgent'
            
            return {
                'polarity': polarity,
                'subjectivity': 0.5,  # Placeholder
                'emotion': emotion,
                'urgency_score': urgency_score
            }
        
        except:
            return {
                'polarity': 0.0,
                'subjectivity': 0.0,
                'emotion': 'neutral',
                'urgency_score': 0.0
            }
    
    async def detect_language_patterns(self, text: str) -> Dict[str, Any]:
        """Detect language patterns indicative of scams"""
        patterns = {
            'urgency_markers': 0,
            'authority_claims': 0,
            'emotional_manipulation': 0,
            'financial_requests': 0,
            'grammar_issues': 0
        }
        
        text_lower = text.lower()
        
        # Urgency markers
        urgency_phrases = [
            'act now', 'limited time', 'expires today', 'urgent', 'immediate',
            'don\'t delay', 'time sensitive', 'deadline', 'last chance'
        ]
        patterns['urgency_markers'] = sum(1 for phrase in urgency_phrases if phrase in text_lower)
        
        # Authority claims
        authority_phrases = [
            'government', 'irs', 'fbi', 'police', 'bank', 'security department',
            'microsoft', 'apple', 'google', 'amazon', 'paypal'
        ]
        patterns['authority_claims'] = sum(1 for phrase in authority_phrases if phrase in text_lower)
        
        # Emotional manipulation
        emotional_phrases = [
            'congratulations', 'winner', 'selected', 'lucky', 'love',
            'help me', 'emergency', 'dying', 'sick', 'stranded'
        ]
        patterns['emotional_manipulation'] = sum(1 for phrase in emotional_phrases if phrase in text_lower)
        
        # Financial requests
        financial_phrases = [
            'send money', 'wire transfer', 'bank account', 'credit card',
            'social security', 'pin number', 'password', 'verify account'
        ]
        patterns['financial_requests'] = sum(1 for phrase in financial_phrases if phrase in text_lower)
        
        # Basic grammar issue detection (simplified)
        sentences = re.split(r'[.!?]+', text)
        grammar_issues = 0
        for sentence in sentences:
            words = sentence.strip().split()
            if len(words) > 3:
                # Check for common grammar issues
                if not sentence.strip():
                    continue
                if not sentence.strip()[0].isupper():
                    grammar_issues += 1
                # Check for excessive capitalization
                caps_ratio = sum(1 for c in sentence if c.isupper()) / max(len(sentence), 1)
                if caps_ratio > 0.3:
                    grammar_issues += 1
        
        patterns['grammar_issues'] = grammar_issues
        
        return patterns
    
    async def comprehensive_analysis(self, text: str) -> Dict[str, Any]:
        """Perform comprehensive NLP analysis"""
        results = {}
        
        # Run all analyses concurrently
        tasks = [
            self.classify_text(text),
            self.extract_advanced_entities(text),
            self.analyze_sentiment_advanced(text),
            self.detect_language_patterns(text)
        ]
        
        classification, entities, sentiment, patterns = await asyncio.gather(*tasks)
        
        results['classification'] = classification
        results['entities'] = entities
        results['sentiment'] = sentiment
        results['language_patterns'] = patterns
        results['analyzed_at'] = datetime.now().isoformat()
        
        # Calculate composite risk score
        risk_score = 0.0
        
        # Classification confidence
        if classification['predicted_class'] != 'legitimate':
            risk_score += classification['confidence'] * 4
        
        # Pattern-based risk
        pattern_risk = (
            patterns['urgency_markers'] * 0.5 +
            patterns['authority_claims'] * 0.3 +
            patterns['emotional_manipulation'] * 0.4 +
            patterns['financial_requests'] * 0.8 +
            patterns['grammar_issues'] * 0.1
        )
        risk_score += min(pattern_risk, 3.0)
        
        # Sentiment-based risk
        if sentiment['emotion'] in ['urgent', 'negative']:
            risk_score += 1.0
        
        # Entity-based risk
        financial_entities = [e for e in entities if e['label'] in ['CREDIT_CARD', 'SSN', 'ACCOUNT_NUMBER', 'MONEY']]
        risk_score += len(financial_entities) * 0.5
        
        results['composite_risk_score'] = min(risk_score, 10.0)
        
        return results
    
    def retrain_model(self, new_training_data: List[Tuple[str, str]]):
        """Retrain the model with new data"""
        if not SKLEARN_AVAILABLE:
            return False
        
        # Combine existing and new training data
        all_data = self.training_data + new_training_data
        texts, labels = zip(*all_data)
        
        # Retrain the classifier
        self.classifier.fit(texts, labels)
        
        # Save the updated model
        try:
            joblib.dump(self.classifier, self.model_path / "scam_classifier.joblib")
            return True
        except:
            return False
