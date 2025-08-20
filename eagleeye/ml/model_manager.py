"""
Model management and versioning system for EagleEye ML models
"""
import json
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import hashlib
import glob

from ..logging_config import LoggerMixin
from ..exceptions import ValidationError, AnalysisError
from .models import ScamDetectionModel, ModelMetrics


@dataclass
class ModelMetadata:
    """Metadata for a trained model"""
    model_id: str
    version: str
    model_type: str
    created_at: datetime
    training_samples: int
    feature_count: int
    performance_metrics: Dict[str, float]
    file_path: Path
    file_size: int
    file_hash: str
    tags: List[str]
    description: str
    is_active: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['file_path'] = str(self.file_path)
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Create from dictionary"""
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['file_path'] = Path(data['file_path'])
        return cls(**data)


@dataclass
class ModelComparison:
    """Comparison between two models"""
    model1_id: str
    model2_id: str
    metric_comparisons: Dict[str, Dict[str, float]]  # metric -> {model1, model2, difference}
    better_model: str
    improvement_percentage: float
    recommendation: str


class ModelManager(LoggerMixin):
    """Manage ML model versions, storage, and deployment"""
    
    def __init__(self, models_dir: Optional[Path] = None):
        self.models_dir = models_dir or Path.cwd() / "models"
        self.models_dir.mkdir(exist_ok=True)
        
        self.metadata_file = self.models_dir / "model_registry.json"
        self.active_model_file = self.models_dir / "active_model.json"
        
        # Load existing metadata
        self.models_registry = self._load_registry()
        
        # Ensure models directory structure
        self._setup_directory_structure()
    
    def register_model(self,
                      model: ScamDetectionModel,
                      metrics: ModelMetrics,
                      training_samples: int,
                      description: str = "",
                      tags: Optional[List[str]] = None) -> str:
        """Register a new trained model"""
        try:
            self.logger.info("Registering new model")
            
            # Generate model ID
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_id = f"{model.model_type}_{timestamp}"
            
            # Save model file
            model_file = self.models_dir / "versions" / f"{model_id}.pkl"
            model_file.parent.mkdir(exist_ok=True)
            model.save_model(model_file)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(model_file)
            
            # Create metadata
            metadata = ModelMetadata(
                model_id=model_id,
                version=model.version,
                model_type=model.model_type,
                created_at=datetime.now(),
                training_samples=training_samples,
                feature_count=len(model.feature_names),
                performance_metrics=metrics.to_dict(),
                file_path=model_file,
                file_size=model_file.stat().st_size,
                file_hash=file_hash,
                tags=tags or [],
                description=description
            )
            
            # Add to registry
            self.models_registry[model_id] = metadata
            self._save_registry()
            
            self.logger.info(f"Model registered with ID: {model_id}")
            return model_id
            
        except Exception as e:
            self.logger.error(f"Failed to register model: {e}")
            raise AnalysisError(f"Model registration failed: {e}", analysis_type="model_registration", cause=e)
    
    def get_model(self, model_id: str) -> Optional[ScamDetectionModel]:
        """Load a model by ID"""
        try:
            if model_id not in self.models_registry:
                self.logger.warning(f"Model {model_id} not found in registry")
                return None
            
            metadata = self.models_registry[model_id]
            
            if not metadata.file_path.exists():
                self.logger.error(f"Model file not found: {metadata.file_path}")
                return None
            
            # Verify file integrity
            current_hash = self._calculate_file_hash(metadata.file_path)
            if current_hash != metadata.file_hash:
                self.logger.warning(f"Model file hash mismatch for {model_id}")
            
            # Load model
            model = ScamDetectionModel(metadata.model_type)
            model.load_model(metadata.file_path)
            
            self.logger.info(f"Loaded model {model_id}")
            return model
            
        except Exception as e:
            self.logger.error(f"Failed to load model {model_id}: {e}")
            return None
    
    def get_active_model(self) -> Optional[ScamDetectionModel]:
        """Get the currently active model"""
        try:
            active_info = self._load_active_model_info()
            if not active_info:
                return None
            
            return self.get_model(active_info['model_id'])
            
        except Exception as e:
            self.logger.error(f"Failed to get active model: {e}")
            return None
    
    def set_active_model(self, model_id: str) -> bool:
        """Set a model as the active/deployed model"""
        try:
            if model_id not in self.models_registry:
                raise ValidationError(f"Model {model_id} not found")
            
            # Update active model info
            active_info = {
                'model_id': model_id,
                'activated_at': datetime.now().isoformat(),
                'metadata': self.models_registry[model_id].to_dict()
            }
            
            with open(self.active_model_file, 'w') as f:
                json.dump(active_info, f, indent=2)
            
            # Update registry to mark active model
            for mid, metadata in self.models_registry.items():
                metadata.is_active = (mid == model_id)
            
            self._save_registry()
            
            # Create symlink to latest
            latest_path = self.models_dir / "latest_model.pkl"
            if latest_path.exists():
                latest_path.unlink()
            
            model_path = self.models_registry[model_id].file_path
            try:
                latest_path.symlink_to(model_path.resolve())
            except OSError:
                # Fallback to copy if symlinks not supported
                shutil.copy2(model_path, latest_path)
            
            self.logger.info(f"Set model {model_id} as active")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set active model: {e}")
            return False
    
    def list_models(self,
                   model_type: Optional[str] = None,
                   tags: Optional[List[str]] = None,
                   limit: Optional[int] = None) -> List[ModelMetadata]:
        """List registered models with optional filtering"""
        try:
            models = list(self.models_registry.values())
            
            # Filter by model type
            if model_type:
                models = [m for m in models if m.model_type == model_type]
            
            # Filter by tags
            if tags:
                models = [m for m in models if any(tag in m.tags for tag in tags)]
            
            # Sort by creation date (newest first)
            models.sort(key=lambda m: m.created_at, reverse=True)
            
            # Apply limit
            if limit:
                models = models[:limit]
            
            return models
            
        except Exception as e:
            self.logger.error(f"Failed to list models: {e}")
            return []
    
    def compare_models(self, model_id1: str, model_id2: str) -> Optional[ModelComparison]:
        """Compare performance metrics of two models"""
        try:
            if model_id1 not in self.models_registry or model_id2 not in self.models_registry:
                raise ValidationError("One or both models not found")
            
            metadata1 = self.models_registry[model_id1]
            metadata2 = self.models_registry[model_id2]
            
            metrics1 = metadata1.performance_metrics
            metrics2 = metadata2.performance_metrics
            
            # Compare common metrics
            metric_comparisons = {}
            common_metrics = set(metrics1.keys()) & set(metrics2.keys())
            
            for metric in common_metrics:
                val1 = metrics1[metric]
                val2 = metrics2[metric]
                difference = val2 - val1
                
                metric_comparisons[metric] = {
                    'model1': val1,
                    'model2': val2,
                    'difference': difference,
                    'improvement_percent': (difference / val1 * 100) if val1 != 0 else 0
                }
            
            # Determine better model (based on F1 score or accuracy)
            key_metric = 'f1_score' if 'f1_score' in common_metrics else 'accuracy'
            
            if key_metric in metric_comparisons:
                better_model = model_id2 if metric_comparisons[key_metric]['difference'] > 0 else model_id1
                improvement = abs(metric_comparisons[key_metric]['improvement_percent'])
            else:
                better_model = model_id1
                improvement = 0.0
            
            # Generate recommendation
            if improvement > 5:
                recommendation = f"Model {better_model.split('_')[0]} shows significant improvement ({improvement:.1f}%)"
            elif improvement > 1:
                recommendation = f"Model {better_model.split('_')[0]} shows modest improvement ({improvement:.1f}%)"
            else:
                recommendation = "Models show similar performance"
            
            return ModelComparison(
                model1_id=model_id1,
                model2_id=model_id2,
                metric_comparisons=metric_comparisons,
                better_model=better_model,
                improvement_percentage=improvement,
                recommendation=recommendation
            )
            
        except Exception as e:
            self.logger.error(f"Failed to compare models: {e}")
            return None
    
    def delete_model(self, model_id: str) -> bool:
        """Delete a model and its files"""
        try:
            if model_id not in self.models_registry:
                raise ValidationError(f"Model {model_id} not found")
            
            metadata = self.models_registry[model_id]
            
            # Don't delete active model
            if metadata.is_active:
                raise ValidationError("Cannot delete active model")
            
            # Delete model file
            if metadata.file_path.exists():
                metadata.file_path.unlink()
            
            # Remove from registry
            del self.models_registry[model_id]
            self._save_registry()
            
            self.logger.info(f"Deleted model {model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete model {model_id}: {e}")
            return False
    
    def cleanup_old_models(self, 
                          keep_count: int = 5,
                          keep_days: int = 30) -> int:
        """Clean up old models, keeping recent and best performing ones"""
        try:
            self.logger.info("Starting model cleanup")
            
            # Get all models sorted by creation date
            all_models = sorted(
                self.models_registry.values(),
                key=lambda m: m.created_at,
                reverse=True
            )
            
            # Always keep active model and recent models
            cutoff_date = datetime.now() - timedelta(days=keep_days)
            models_to_keep = set()
            deleted_count = 0
            
            # Keep active model
            for model in all_models:
                if model.is_active:
                    models_to_keep.add(model.model_id)
            
            # Keep recent models
            recent_models = [m for m in all_models if m.created_at > cutoff_date]
            for model in recent_models[:keep_count]:
                models_to_keep.add(model.model_id)
            
            # Keep best performing models of each type
            by_type = {}
            for model in all_models:
                if model.model_type not in by_type:
                    by_type[model.model_type] = []
                by_type[model.model_type].append(model)
            
            for model_type, models in by_type.items():
                # Sort by F1 score or accuracy
                key_metric = 'f1_score'
                if all(key_metric in m.performance_metrics for m in models):
                    models.sort(key=lambda m: m.performance_metrics[key_metric], reverse=True)
                else:
                    models.sort(key=lambda m: m.performance_metrics.get('accuracy', 0), reverse=True)
                
                # Keep top 2 performers of each type
                for model in models[:2]:
                    models_to_keep.add(model.model_id)
            
            # Delete models not in keep set
            models_to_delete = [m for m in all_models if m.model_id not in models_to_keep]
            
            for model in models_to_delete:
                if self.delete_model(model.model_id):
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old models")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Model cleanup failed: {e}")
            return 0
    
    def export_model(self, model_id: str, export_path: Path) -> bool:
        """Export a model for external use"""
        try:
            if model_id not in self.models_registry:
                raise ValidationError(f"Model {model_id} not found")
            
            metadata = self.models_registry[model_id]
            export_path.mkdir(parents=True, exist_ok=True)
            
            # Copy model file
            model_file = export_path / f"{model_id}.pkl"
            shutil.copy2(metadata.file_path, model_file)
            
            # Export metadata
            metadata_file = export_path / f"{model_id}_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata.to_dict(), f, indent=2)
            
            # Create README
            readme_file = export_path / "README.md"
            with open(readme_file, 'w') as f:
                f.write(f"""# EagleEye ML Model Export

## Model Information
- **Model ID**: {model_id}
- **Type**: {metadata.model_type}
- **Version**: {metadata.version}
- **Created**: {metadata.created_at.strftime('%Y-%m-%d %H:%M:%S')}
- **Training Samples**: {metadata.training_samples}
- **Features**: {metadata.feature_count}

## Performance Metrics
""")
                for metric, value in metadata.performance_metrics.items():
                    f.write(f"- **{metric}**: {value:.4f}\n")
                
                f.write(f"""
## Description
{metadata.description}

## Tags
{', '.join(metadata.tags)}

## Usage
Load the model using the EagleEye ScamDetectionModel class:

```python
from eagleeye.ml.models import ScamDetectionModel
model = ScamDetectionModel('{metadata.model_type}')
model.load_model('{model_id}.pkl')
```
""")
            
            self.logger.info(f"Exported model {model_id} to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export model {model_id}: {e}")
            return False
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about registered models"""
        try:
            models = list(self.models_registry.values())
            
            if not models:
                return {"total_models": 0}
            
            # Count by type
            by_type = {}
            for model in models:
                by_type[model.model_type] = by_type.get(model.model_type, 0) + 1
            
            # Performance statistics
            f1_scores = [m.performance_metrics.get('f1_score', 0) for m in models]
            accuracies = [m.performance_metrics.get('accuracy', 0) for m in models]
            
            # Find best model
            best_model = max(models, key=lambda m: m.performance_metrics.get('f1_score', 0))
            
            # Storage usage
            total_size = sum(m.file_size for m in models)
            
            return {
                "total_models": len(models),
                "models_by_type": by_type,
                "performance_stats": {
                    "avg_f1_score": sum(f1_scores) / len(f1_scores) if f1_scores else 0,
                    "avg_accuracy": sum(accuracies) / len(accuracies) if accuracies else 0,
                    "best_model_id": best_model.model_id,
                    "best_f1_score": best_model.performance_metrics.get('f1_score', 0)
                },
                "storage_stats": {
                    "total_size_mb": total_size / (1024 * 1024),
                    "avg_size_mb": (total_size / len(models)) / (1024 * 1024)
                },
                "active_model": next((m.model_id for m in models if m.is_active), None)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get model stats: {e}")
            return {"error": str(e)}
    
    def _setup_directory_structure(self):
        """Setup directory structure for models"""
        (self.models_dir / "versions").mkdir(exist_ok=True)
        (self.models_dir / "exports").mkdir(exist_ok=True)
        (self.models_dir / "backups").mkdir(exist_ok=True)
    
    def _load_registry(self) -> Dict[str, ModelMetadata]:
        """Load models registry from file"""
        try:
            if not self.metadata_file.exists():
                return {}
            
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
            
            registry = {}
            for model_id, model_data in data.items():
                registry[model_id] = ModelMetadata.from_dict(model_data)
            
            return registry
            
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
            return {}
    
    def _save_registry(self):
        """Save models registry to file"""
        try:
            data = {}
            for model_id, metadata in self.models_registry.items():
                data[model_id] = metadata.to_dict()
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save registry: {e}")
    
    def _load_active_model_info(self) -> Optional[Dict[str, Any]]:
        """Load active model information"""
        try:
            if not self.active_model_file.exists():
                return None
            
            with open(self.active_model_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.error(f"Failed to load active model info: {e}")
            return None
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()


# Global model manager instance
_model_manager: Optional[ModelManager] = None


def get_model_manager() -> ModelManager:
    """Get the global model manager instance"""
    global _model_manager
    if _model_manager is None:
        _model_manager = ModelManager()
    return _model_manager