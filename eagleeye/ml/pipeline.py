"""
ML Pipeline orchestration for EagleEye scam detection
"""
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
import asyncio
import joblib

from ..logging_config import LoggerMixin
from ..exceptions import AnalysisError, ValidationError
from ..database import get_database, ScamRecord
from .models import ScamDetectionModel, ModelTrainer, ModelEvaluator, PredictionResult
from .features import FeatureExtractor


@dataclass
class PipelineConfig:
    """Configuration for ML pipeline"""
    model_type: str = "random_forest"
    feature_extraction: bool = True
    hyperparameter_optimization: bool = False
    cross_validation: bool = True
    train_test_split: float = 0.8
    min_samples: int = 100
    retrain_threshold_days: int = 7
    performance_threshold: float = 0.7


@dataclass
class PipelineResult:
    """Result from pipeline execution"""
    success: bool
    model_path: Optional[Path] = None
    metrics: Optional[Dict[str, float]] = None
    feature_importance: Optional[Dict[str, float]] = None
    predictions: Optional[List[PredictionResult]] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None


class MLPipeline(LoggerMixin):
    """Complete ML pipeline for scam detection"""
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.trainer = ModelTrainer()
        self.evaluator = ModelEvaluator()
        self.database = get_database()
        
        # Pipeline state
        self.is_trained = False
        self.last_training = None
        self.training_data_size = 0
    
    async def train_pipeline(self, 
                           training_data: Optional[pd.DataFrame] = None,
                           labels: Optional[pd.Series] = None) -> PipelineResult:
        """Complete training pipeline"""
        start_time = datetime.now()
        
        try:
            self.logger.info("Starting ML pipeline training")
            
            # Prepare training data
            if training_data is None or labels is None:
                X, y = await self._prepare_training_data()
            else:
                X, y = training_data, labels
            
            # Validate data
            if len(X) < self.config.min_samples:
                raise ValidationError(f"Insufficient training data: {len(X)} < {self.config.min_samples}")
            
            # Train model
            if self.config.hyperparameter_optimization:
                self.logger.info("Training with hyperparameter optimization")
                self.model = self.trainer.hyperparameter_optimization(X, y, self.config.model_type)
            else:
                self.logger.info(f"Training {self.config.model_type} model")
                self.model = ScamDetectionModel(self.config.model_type)
                metrics = self.model.train(X, y)
            
            # Cross-validation
            cv_results = None
            if self.config.cross_validation and self.model:
                self.logger.info("Performing cross-validation")
                cv_results = self.evaluator.cross_validate(self.model, X, y)
            
            # Feature importance
            feature_importance = None
            if self.model:
                try:
                    feature_importance = self.evaluator.feature_importance(self.model)
                except Exception as e:
                    self.logger.warning(f"Could not compute feature importance: {e}")
            
            # Save model
            model_path = None
            if self.model:
                model_path = await self._save_model()
            
            # Update pipeline state
            self.is_trained = True
            self.last_training = datetime.now()
            self.training_data_size = len(X)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            self.logger.info(f"Pipeline training completed in {execution_time:.2f}s")
            
            return PipelineResult(
                success=True,
                model_path=model_path,
                metrics=cv_results or (metrics.to_dict() if 'metrics' in locals() else None),
                feature_importance=feature_importance,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Pipeline training failed: {e}")
            
            return PipelineResult(
                success=False,
                error_message=str(e),
                execution_time=execution_time
            )
    
    async def predict_pipeline(self, 
                             content: Dict[str, Any]) -> PipelineResult:
        """Complete prediction pipeline"""
        start_time = datetime.now()
        
        try:
            if not self.is_trained or not self.model:
                # Try to load existing model
                await self._load_model()
                
                if not self.model:
                    raise AnalysisError("No trained model available", analysis_type="prediction")
            
            # Extract content
            text = content.get('text')
            url = content.get('url') 
            phone = content.get('phone')
            
            # Make prediction
            result = self.model.predict_from_content(text, url, phone)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return PipelineResult(
                success=True,
                predictions=[result],
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Pipeline prediction failed: {e}")
            
            return PipelineResult(
                success=False,
                error_message=str(e),
                execution_time=execution_time
            )
    
    async def batch_predict(self, 
                          content_list: List[Dict[str, Any]]) -> PipelineResult:
        """Batch prediction pipeline"""
        start_time = datetime.now()
        
        try:
            if not self.is_trained or not self.model:
                await self._load_model()
                
                if not self.model:
                    raise AnalysisError("No trained model available", analysis_type="batch_prediction")
            
            predictions = []
            
            for content in content_list:
                try:
                    text = content.get('text')
                    url = content.get('url')
                    phone = content.get('phone')
                    
                    result = self.model.predict_from_content(text, url, phone)
                    predictions.append(result)
                    
                except Exception as e:
                    self.logger.warning(f"Failed to predict for content: {e}")
                    # Continue with next item
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return PipelineResult(
                success=True,
                predictions=predictions,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Batch prediction failed: {e}")
            
            return PipelineResult(
                success=False,
                error_message=str(e),
                execution_time=execution_time
            )
    
    async def evaluate_pipeline(self, 
                              test_data: Optional[pd.DataFrame] = None,
                              test_labels: Optional[pd.Series] = None) -> PipelineResult:
        """Evaluate pipeline performance"""
        start_time = datetime.now()
        
        try:
            if not self.is_trained or not self.model:
                await self._load_model()
                
                if not self.model:
                    raise AnalysisError("No trained model available", analysis_type="evaluation")
            
            # Prepare test data if not provided
            if test_data is None or test_labels is None:
                X, y = await self._prepare_training_data()
                # Use a subset for testing
                test_size = min(1000, len(X) // 5)
                test_data = X.sample(n=test_size, random_state=42)
                test_labels = y.loc[test_data.index]
            
            # Perform evaluation
            cv_results = self.evaluator.cross_validate(self.model, test_data, test_labels)
            feature_importance = self.evaluator.feature_importance(self.model)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return PipelineResult(
                success=True,
                metrics=cv_results,
                feature_importance=feature_importance,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Pipeline evaluation failed: {e}")
            
            return PipelineResult(
                success=False,
                error_message=str(e),
                execution_time=execution_time
            )
    
    async def retrain_if_needed(self) -> bool:
        """Check if retraining is needed and perform it"""
        try:
            # Check if enough time has passed since last training
            if (self.last_training and 
                (datetime.now() - self.last_training).days < self.config.retrain_threshold_days):
                return False
            
            # Check if we have enough new data
            current_data_size = await self._get_current_data_size()
            if current_data_size <= self.training_data_size * 1.1:  # 10% increase threshold
                return False
            
            # Check model performance
            eval_result = await self.evaluate_pipeline()
            if (eval_result.success and eval_result.metrics and 
                eval_result.metrics.get('f1_weighted_mean', 0) >= self.config.performance_threshold):
                return False
            
            # Perform retraining
            self.logger.info("Retraining model due to performance degradation or new data")
            train_result = await self.train_pipeline()
            
            return train_result.success
            
        except Exception as e:
            self.logger.error(f"Retrain check failed: {e}")
            return False
    
    async def _prepare_training_data(self) -> Tuple[pd.DataFrame, pd.Series]:
        """Prepare training data from database"""
        try:
            self.logger.info("Preparing training data from database")
            
            # Get all scam records
            scam_records = self.database.search_scams(limit=10000)
            
            if len(scam_records) < self.config.min_samples:
                raise ValidationError(f"Insufficient data in database: {len(scam_records)}")
            
            # Extract features and labels
            features_list = []
            labels = []
            
            for record in scam_records:
                try:
                    # Extract features from record
                    features = self.feature_extractor.extract_combined_features(
                        text=f"{record.title} {record.description}",
                        url=record.url,
                        phone=record.phone
                    )
                    
                    if features:
                        features_list.append(features)
                        # Use scam_type as label, or 'scam' if severity > 5
                        label = record.scam_type if record.scam_type else ('scam' if record.severity > 5.0 else 'legitimate')
                        labels.append(label)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to extract features from record {record.id}: {e}")
                    continue
            
            if not features_list:
                raise ValidationError("No valid features could be extracted")
            
            # Convert to DataFrame
            X = pd.DataFrame(features_list)
            y = pd.Series(labels)
            
            self.logger.info(f"Prepared {len(X)} training samples with {len(X.columns)} features")
            return X, y
            
        except Exception as e:
            self.logger.error(f"Failed to prepare training data: {e}")
            raise AnalysisError(f"Training data preparation failed: {e}", analysis_type="data_preparation", cause=e)
    
    async def _save_model(self) -> Path:
        """Save the trained model"""
        try:
            models_dir = Path.cwd() / "models"
            models_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_path = models_dir / f"scam_detection_model_{timestamp}.pkl"
            
            self.model.save_model(model_path)
            
            # Also save as latest
            latest_path = models_dir / "latest_model.pkl"
            self.model.save_model(latest_path)
            
            return model_path
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")
            raise AnalysisError(f"Model save failed: {e}", analysis_type="model_save", cause=e)
    
    async def _load_model(self) -> bool:
        """Load the latest trained model"""
        try:
            models_dir = Path.cwd() / "models"
            latest_path = models_dir / "latest_model.pkl"
            
            if not latest_path.exists():
                self.logger.warning("No saved model found")
                return False
            
            self.model = ScamDetectionModel(self.config.model_type)
            self.model.load_model(latest_path)
            self.is_trained = True
            
            self.logger.info("Loaded trained model successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False
    
    async def _get_current_data_size(self) -> int:
        """Get current size of training data"""
        try:
            stats = self.database.get_stats()
            return stats.get('total_records', 0)
        except Exception:
            return 0


class BatchProcessor(LoggerMixin):
    """Batch processing for large datasets"""
    
    def __init__(self, pipeline: MLPipeline, batch_size: int = 100):
        self.pipeline = pipeline
        self.batch_size = batch_size
    
    async def process_database_records(self, 
                                     hours_back: Optional[int] = None) -> Dict[str, Any]:
        """Process all records in database for predictions"""
        try:
            self.logger.info("Starting batch processing of database records")
            
            # Get records to process
            records = self.pipeline.database.search_scams(
                hours_back=hours_back,
                limit=10000
            )
            
            if not records:
                return {"processed": 0, "predictions": []}
            
            # Process in batches
            all_predictions = []
            processed_count = 0
            
            for i in range(0, len(records), self.batch_size):
                batch_records = records[i:i + self.batch_size]
                
                # Convert records to content format
                content_list = []
                for record in batch_records:
                    content = {
                        'text': f"{record.title} {record.description}",
                        'url': record.url,
                        'phone': record.phone,
                        'record_id': record.id
                    }
                    content_list.append(content)
                
                # Make predictions
                result = await self.pipeline.batch_predict(content_list)
                
                if result.success and result.predictions:
                    all_predictions.extend(result.predictions)
                    processed_count += len(batch_records)
                    
                    self.logger.info(f"Processed batch {i//self.batch_size + 1}, total: {processed_count}")
                
                # Small delay to prevent overwhelming the system
                await asyncio.sleep(0.1)
            
            self.logger.info(f"Batch processing completed: {processed_count} records")
            
            return {
                "processed": processed_count,
                "predictions": all_predictions,
                "high_risk_count": sum(1 for p in all_predictions if p.risk_score > 7.0),
                "average_risk": np.mean([p.risk_score for p in all_predictions]) if all_predictions else 0.0
            }
            
        except Exception as e:
            self.logger.error(f"Batch processing failed: {e}")
            raise AnalysisError(f"Batch processing failed: {e}", analysis_type="batch_processing", cause=e)