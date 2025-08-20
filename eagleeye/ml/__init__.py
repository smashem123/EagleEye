"""
Machine Learning module for EagleEye scam detection
"""

from .models import ScamDetectionModel, ModelTrainer, ModelEvaluator
from .features import FeatureExtractor, TextFeatures, URLFeatures, PhoneFeatures
from .pipeline import MLPipeline
from .model_manager import ModelManager

__all__ = [
    'ScamDetectionModel',
    'ModelTrainer', 
    'ModelEvaluator',
    'FeatureExtractor',
    'TextFeatures',
    'URLFeatures', 
    'PhoneFeatures',
    'MLPipeline',
    'ModelManager'
]