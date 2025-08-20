"""
Machine learning models for scam detection
"""
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_class_weight

from ..logging_config import LoggerMixin
from ..exceptions import AnalysisError, ValidationError
from .features import FeatureExtractor


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    auc_score: float = 0.0
    confusion_matrix: Optional[np.ndarray] = None
    classification_report: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'auc_score': self.auc_score,
            'confusion_matrix': self.confusion_matrix.tolist() if self.confusion_matrix is not None else None,
            'classification_report': self.classification_report
        }


@dataclass
class PredictionResult:
    """Model prediction result"""
    predicted_class: str
    confidence: float
    probabilities: Dict[str, float]
    risk_score: float
    model_version: str
    features_used: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'predicted_class': self.predicted_class,
            'confidence': self.confidence,
            'probabilities': self.probabilities,
            'risk_score': self.risk_score,
            'model_version': self.model_version,
            'features_used': self.features_used
        }


class ScamDetectionModel(LoggerMixin):
    """Main scam detection model class"""
    
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.version = "1.0.0"
        self.trained_at = None
        self.feature_extractor = FeatureExtractor()
        
        # Initialize model based on type
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML model based on type"""
        model_configs = {
            "random_forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced'
            ),
            "gradient_boost": GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            ),
            "logistic_regression": LogisticRegression(
                max_iter=1000,
                random_state=42,
                class_weight='balanced'
            ),
            "svm": SVC(
                kernel='rbf',
                probability=True,
                random_state=42,
                class_weight='balanced'
            ),
            "naive_bayes": MultinomialNB(alpha=1.0)
        }
        
        if self.model_type not in model_configs:
            raise ValidationError(f"Unknown model type: {self.model_type}")
        
        self.model = model_configs[self.model_type]
        self.logger.info(f"Initialized {self.model_type} model")
    
    def train(self, X: Union[pd.DataFrame, np.ndarray], y: Union[pd.Series, np.ndarray]) -> ModelMetrics:
        """Train the model on provided data"""
        try:
            self.logger.info(f"Starting training with {len(X)} samples")
            
            # Validate input data
            if len(X) != len(y):
                raise ValidationError("X and y must have the same length")
            
            if len(X) < 10:
                raise ValidationError("Need at least 10 samples for training")
            
            # Convert to DataFrame if needed
            if isinstance(X, np.ndarray):
                X = pd.DataFrame(X)
            
            # Store feature names
            self.feature_names = list(X.columns)
            
            # Encode labels
            y_encoded = self.label_encoder.fit_transform(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            self.trained_at = datetime.now()
            
            # Evaluate model
            metrics = self._evaluate_model(X_test_scaled, y_test)
            
            self.logger.info(f"Training completed. Accuracy: {metrics.accuracy:.3f}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            raise AnalysisError(f"Model training failed: {e}", analysis_type="model_training", cause=e)
    
    def predict(self, X: Union[pd.DataFrame, np.ndarray, Dict[str, Any]]) -> PredictionResult:
        """Make prediction on new data"""
        try:
            if self.model is None:
                raise AnalysisError("Model not trained yet", analysis_type="prediction")
            
            # Handle different input types
            if isinstance(X, dict):
                X = pd.DataFrame([X])
            elif isinstance(X, np.ndarray):
                X = pd.DataFrame(X, columns=self.feature_names)
            
            # Ensure all required features are present
            missing_features = set(self.feature_names) - set(X.columns)
            if missing_features:
                # Fill missing features with zeros
                for feature in missing_features:
                    X[feature] = 0.0
            
            # Reorder columns to match training
            X = X[self.feature_names]
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Make prediction
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            # Get class names
            class_names = self.label_encoder.classes_
            prob_dict = dict(zip(class_names, probabilities))
            
            # Calculate confidence and risk score
            confidence = max(probabilities)
            predicted_class = class_names[prediction]
            
            # Risk score: probability of being a scam
            scam_prob = prob_dict.get('scam', prob_dict.get('malicious', 0.0))
            risk_score = scam_prob * 10  # Scale to 0-10
            
            result = PredictionResult(
                predicted_class=predicted_class,
                confidence=confidence,
                probabilities=prob_dict,
                risk_score=risk_score,
                model_version=self.version,
                features_used=self.feature_names
            )
            
            self.logger.debug(f"Prediction: {predicted_class} (confidence: {confidence:.3f})")
            return result
            
        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            raise AnalysisError(f"Model prediction failed: {e}", analysis_type="prediction", cause=e)
    
    def predict_from_content(self, 
                           text: Optional[str] = None,
                           url: Optional[str] = None,
                           phone: Optional[str] = None) -> PredictionResult:
        """Make prediction from raw content"""
        try:
            # Extract features
            features = self.feature_extractor.extract_combined_features(text, url, phone)
            
            if not features:
                raise ValidationError("No features could be extracted from input")
            
            return self.predict(features)
            
        except Exception as e:
            self.logger.error(f"Content prediction failed: {e}")
            raise AnalysisError(f"Content prediction failed: {e}", analysis_type="content_prediction", cause=e)
    
    def _evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> ModelMetrics:
        """Evaluate model performance"""
        try:
            # Make predictions
            y_pred = self.model.predict(X_test)
            y_proba = self.model.predict_proba(X_test)
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted')
            recall = recall_score(y_test, y_pred, average='weighted')
            f1 = f1_score(y_test, y_pred, average='weighted')
            
            # AUC score (for binary classification)
            auc = 0.0
            if len(np.unique(y_test)) == 2:
                auc = roc_auc_score(y_test, y_proba[:, 1])
            
            # Confusion matrix and classification report
            cm = confusion_matrix(y_test, y_pred)
            report = classification_report(y_test, y_pred, target_names=self.label_encoder.classes_)
            
            return ModelMetrics(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                auc_score=auc,
                confusion_matrix=cm,
                classification_report=report
            )
            
        except Exception as e:
            self.logger.error(f"Model evaluation failed: {e}")
            raise AnalysisError(f"Model evaluation failed: {e}", analysis_type="evaluation", cause=e)
    
    def save_model(self, filepath: Path):
        """Save trained model to file"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'feature_names': self.feature_names,
                'model_type': self.model_type,
                'version': self.version,
                'trained_at': self.trained_at
            }
            
            filepath.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(model_data, filepath)
            
            self.logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")
            raise AnalysisError(f"Model save failed: {e}", analysis_type="model_save", cause=e)
    
    def load_model(self, filepath: Path):
        """Load trained model from file"""
        try:
            if not filepath.exists():
                raise ValidationError(f"Model file not found: {filepath}")
            
            model_data = joblib.load(filepath)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.feature_names = model_data['feature_names']
            self.model_type = model_data['model_type']
            self.version = model_data['version']
            self.trained_at = model_data['trained_at']
            
            self.logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            raise AnalysisError(f"Model load failed: {e}", analysis_type="model_load", cause=e)


class ModelTrainer(LoggerMixin):
    """Model training and hyperparameter optimization"""
    
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.best_score = 0.0
    
    def train_multiple_models(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, ModelMetrics]:
        """Train multiple model types and compare performance"""
        try:
            model_types = ["random_forest", "gradient_boost", "logistic_regression", "svm"]
            results = {}
            
            for model_type in model_types:
                self.logger.info(f"Training {model_type} model")
                
                model = ScamDetectionModel(model_type)
                metrics = model.train(X, y)
                
                self.models[model_type] = model
                results[model_type] = metrics
                
                # Track best model
                if metrics.f1_score > self.best_score:
                    self.best_score = metrics.f1_score
                    self.best_model = model
            
            self.logger.info(f"Best model: {self.best_model.model_type} (F1: {self.best_score:.3f})")
            return results
            
        except Exception as e:
            self.logger.error(f"Multi-model training failed: {e}")
            raise AnalysisError(f"Multi-model training failed: {e}", analysis_type="multi_training", cause=e)
    
    def hyperparameter_optimization(self, X: pd.DataFrame, y: pd.Series, model_type: str = "random_forest") -> ScamDetectionModel:
        """Perform hyperparameter optimization"""
        try:
            self.logger.info(f"Starting hyperparameter optimization for {model_type}")
            
            # Define parameter grids
            param_grids = {
                "random_forest": {
                    'n_estimators': [50, 100, 200],
                    'max_depth': [5, 10, 15, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4]
                },
                "gradient_boost": {
                    'n_estimators': [50, 100, 150],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'max_depth': [3, 5, 7]
                },
                "logistic_regression": {
                    'C': [0.1, 1.0, 10.0],
                    'solver': ['liblinear', 'lbfgs']
                }
            }
            
            if model_type not in param_grids:
                raise ValidationError(f"Hyperparameter optimization not supported for {model_type}")
            
            # Initialize base model
            base_model = ScamDetectionModel(model_type)
            
            # Prepare data
            y_encoded = base_model.label_encoder.fit_transform(y)
            X_scaled = base_model.scaler.fit_transform(X)
            
            # Grid search
            grid_search = GridSearchCV(
                base_model.model,
                param_grids[model_type],
                cv=5,
                scoring='f1_weighted',
                n_jobs=-1,
                verbose=1
            )
            
            grid_search.fit(X_scaled, y_encoded)
            
            # Create optimized model
            optimized_model = ScamDetectionModel(model_type)
            optimized_model.model = grid_search.best_estimator_
            optimized_model.scaler = base_model.scaler
            optimized_model.label_encoder = base_model.label_encoder
            optimized_model.feature_names = list(X.columns)
            optimized_model.trained_at = datetime.now()
            
            self.logger.info(f"Best parameters: {grid_search.best_params_}")
            self.logger.info(f"Best score: {grid_search.best_score_:.3f}")
            
            return optimized_model
            
        except Exception as e:
            self.logger.error(f"Hyperparameter optimization failed: {e}")
            raise AnalysisError(f"Hyperparameter optimization failed: {e}", analysis_type="hyperopt", cause=e)


class ModelEvaluator(LoggerMixin):
    """Model evaluation and validation"""
    
    def cross_validate(self, model: ScamDetectionModel, X: pd.DataFrame, y: pd.Series, cv: int = 5) -> Dict[str, float]:
        """Perform cross-validation"""
        try:
            if model.model is None:
                raise AnalysisError("Model not trained", analysis_type="cross_validation")
            
            # Prepare data
            y_encoded = model.label_encoder.transform(y)
            X_scaled = model.scaler.transform(X)
            
            # Cross-validation scores
            scoring_metrics = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted']
            cv_results = {}
            
            for metric in scoring_metrics:
                scores = cross_val_score(model.model, X_scaled, y_encoded, cv=cv, scoring=metric)
                cv_results[f"{metric}_mean"] = scores.mean()
                cv_results[f"{metric}_std"] = scores.std()
            
            self.logger.info(f"Cross-validation completed (CV={cv})")
            return cv_results
            
        except Exception as e:
            self.logger.error(f"Cross-validation failed: {e}")
            raise AnalysisError(f"Cross-validation failed: {e}", analysis_type="cross_validation", cause=e)
    
    def feature_importance(self, model: ScamDetectionModel) -> Dict[str, float]:
        """Get feature importance scores"""
        try:
            if model.model is None:
                raise AnalysisError("Model not trained", analysis_type="feature_importance")
            
            # Get feature importance based on model type
            if hasattr(model.model, 'feature_importances_'):
                importance_scores = model.model.feature_importances_
            elif hasattr(model.model, 'coef_'):
                importance_scores = np.abs(model.model.coef_[0])
            else:
                raise AnalysisError(f"Feature importance not supported for {model.model_type}")
            
            # Create feature importance dictionary
            feature_importance = dict(zip(model.feature_names, importance_scores))
            
            # Sort by importance
            sorted_features = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
            
            self.logger.info("Feature importance calculated")
            return sorted_features
            
        except Exception as e:
            self.logger.error(f"Feature importance calculation failed: {e}")
            raise AnalysisError(f"Feature importance failed: {e}", analysis_type="feature_importance", cause=e)