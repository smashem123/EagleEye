"""
Voice/Audio analysis for scam detection
Real-time voice scam detection and analysis
"""
import asyncio
import wave
import io
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import hashlib
import re

try:
    import speech_recognition as sr
    from pydub import AudioSegment
    import librosa
    import numpy as np
    AUDIO_AVAILABLE = True
except ImportError:
    AUDIO_AVAILABLE = False

from .text_analyzer import TextAnalyzer, ScamTextResult, ScamType


@dataclass
class VoiceScamResult:
    """Result of voice/audio analysis for scam detection"""
    audio_hash: str
    transcription: str
    text_analysis: Optional[ScamTextResult]
    voice_features: Dict[str, Any]
    audio_quality: float
    confidence: float
    detected_at: datetime
    source_file: Optional[str] = None
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'audio_hash': self.audio_hash,
            'transcription': self.transcription,
            'text_analysis': self.text_analysis.to_dict() if self.text_analysis else None,
            'voice_features': self.voice_features,
            'audio_quality': self.audio_quality,
            'confidence': self.confidence,
            'detected_at': self.detected_at.isoformat(),
            'source_file': self.source_file,
            'duration_seconds': self.duration_seconds
        }


class VoiceAnalyzer:
    """Advanced voice analyzer for scam detection"""
    
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.recognizer = sr.Recognizer() if AUDIO_AVAILABLE else None
        
        # Voice scam indicators
        self.voice_patterns = {
            'robocall_indicators': [
                r'this is not a sales call',
                r'you have been selected',
                r'congratulations',
                r'final notice',
                r'press \d+ to',
                r'stay on the line',
                r'do not hang up'
            ],
            'tech_support_phrases': [
                r'microsoft support',
                r'windows support',
                r'computer virus',
                r'security alert',
                r'remote access',
                r'your computer is infected',
                r'suspicious activity detected'
            ],
            'financial_scam_phrases': [
                r'credit card',
                r'bank account',
                r'social security',
                r'verify your account',
                r'payment required',
                r'overdue payment',
                r'account suspended'
            ],
            'urgency_phrases': [
                r'immediate action',
                r'within 24 hours',
                r'expires today',
                r'limited time',
                r'act now',
                r'urgent',
                r'emergency'
            ]
        }
    
    def _get_audio_hash(self, audio_data: bytes) -> str:
        """Generate hash for audio deduplication"""
        return hashlib.sha256(audio_data).hexdigest()[:16]
    
    async def analyze_audio_file(self, file_path: str) -> VoiceScamResult:
        """Analyze audio file for scam indicators"""
        if not AUDIO_AVAILABLE:
            raise ImportError("Audio analysis requires speech_recognition, pydub, and librosa packages")
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Audio file not found: {file_path}")
        
        # Read audio file
        with open(file_path, 'rb') as f:
            audio_data = f.read()
        
        audio_hash = self._get_audio_hash(audio_data)
        
        # Convert audio to supported format if needed
        audio_segment = AudioSegment.from_file(str(file_path))
        duration_seconds = len(audio_segment) / 1000.0
        
        # Convert to WAV for speech recognition
        wav_data = io.BytesIO()
        audio_segment.export(wav_data, format="wav")
        wav_data.seek(0)
        
        # Transcribe audio
        transcription = await self._transcribe_audio(wav_data)
        
        # Analyze voice features
        voice_features = await self._analyze_voice_features(audio_segment)
        
        # Calculate audio quality
        audio_quality = self._calculate_audio_quality(audio_segment)
        
        # Analyze transcribed text for scams
        text_analysis = None
        if transcription:
            text_analysis = await self.text_analyzer.analyze_text(
                transcription, 
                source_type="voice_call"
            )
        
        # Calculate overall confidence
        confidence = self._calculate_voice_confidence(
            transcription, voice_features, audio_quality, text_analysis
        )
        
        return VoiceScamResult(
            audio_hash=audio_hash,
            transcription=transcription,
            text_analysis=text_analysis,
            voice_features=voice_features,
            audio_quality=audio_quality,
            confidence=confidence,
            detected_at=datetime.now(),
            source_file=str(file_path),
            duration_seconds=duration_seconds
        )
    
    async def _transcribe_audio(self, audio_data: io.BytesIO) -> str:
        """Transcribe audio to text using speech recognition"""
        try:
            with sr.AudioFile(audio_data) as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.record(source)
            
            # Try multiple recognition engines
            transcription = ""
            
            # Try Google Speech Recognition (free)
            try:
                transcription = self.recognizer.recognize_google(audio)
            except sr.UnknownValueError:
                pass
            except sr.RequestError:
                pass
            
            # Fallback to offline recognition if available
            if not transcription:
                try:
                    transcription = self.recognizer.recognize_sphinx(audio)
                except:
                    pass
            
            return transcription
            
        except Exception as e:
            return ""
    
    async def _analyze_voice_features(self, audio_segment: AudioSegment) -> Dict[str, Any]:
        """Analyze voice characteristics for scam indicators"""
        features = {
            'duration_ms': len(audio_segment),
            'sample_rate': audio_segment.frame_rate,
            'channels': audio_segment.channels,
            'loudness': audio_segment.dBFS,
            'is_robocall_likely': False,
            'voice_quality': 'unknown',
            'background_noise': 'unknown'
        }
        
        try:
            # Convert to numpy array for analysis
            samples = audio_segment.get_array_of_samples()
            audio_array = np.array(samples).astype(np.float32)
            
            if audio_segment.channels == 2:
                audio_array = audio_array.reshape((-1, 2)).mean(axis=1)
            
            # Normalize
            audio_array = audio_array / np.max(np.abs(audio_array))
            
            # Basic audio analysis
            features.update({
                'zero_crossing_rate': self._calculate_zero_crossing_rate(audio_array),
                'spectral_centroid': self._calculate_spectral_centroid(audio_array, audio_segment.frame_rate),
                'rms_energy': np.sqrt(np.mean(audio_array**2)),
                'silence_ratio': self._calculate_silence_ratio(audio_array)
            })
            
            # Robocall detection heuristics
            features['is_robocall_likely'] = self._detect_robocall_patterns(features)
            
        except Exception as e:
            # Continue with basic features if advanced analysis fails
            pass
        
        return features
    
    def _calculate_zero_crossing_rate(self, audio_array: np.ndarray) -> float:
        """Calculate zero crossing rate (indicator of voice vs synthetic)"""
        zero_crossings = np.sum(np.diff(np.sign(audio_array)) != 0)
        return zero_crossings / len(audio_array)
    
    def _calculate_spectral_centroid(self, audio_array: np.ndarray, sample_rate: int) -> float:
        """Calculate spectral centroid (brightness of sound)"""
        try:
            spectral_centroids = librosa.feature.spectral_centroid(y=audio_array, sr=sample_rate)[0]
            return np.mean(spectral_centroids)
        except:
            return 0.0
    
    def _calculate_silence_ratio(self, audio_array: np.ndarray, threshold: float = 0.01) -> float:
        """Calculate ratio of silence in audio"""
        silent_samples = np.sum(np.abs(audio_array) < threshold)
        return silent_samples / len(audio_array)
    
    def _detect_robocall_patterns(self, features: Dict[str, Any]) -> bool:
        """Detect if audio has robocall characteristics"""
        indicators = 0
        
        # Very consistent volume (robocalls often have flat audio)
        if features.get('rms_energy', 0) > 0.1 and features.get('silence_ratio', 0) < 0.1:
            indicators += 1
        
        # Unusual spectral characteristics
        spectral_centroid = features.get('spectral_centroid', 0)
        if spectral_centroid > 3000 or spectral_centroid < 500:
            indicators += 1
        
        # Low zero crossing rate (synthetic voice)
        if features.get('zero_crossing_rate', 0) < 0.05:
            indicators += 1
        
        return indicators >= 2
    
    def _calculate_audio_quality(self, audio_segment: AudioSegment) -> float:
        """Calculate audio quality score (0-1)"""
        quality_score = 0.5  # Base score
        
        # Sample rate quality
        if audio_segment.frame_rate >= 44100:
            quality_score += 0.2
        elif audio_segment.frame_rate >= 22050:
            quality_score += 0.1
        
        # Loudness quality (not too quiet, not clipping)
        if -20 <= audio_segment.dBFS <= -6:
            quality_score += 0.2
        elif -30 <= audio_segment.dBFS <= -3:
            quality_score += 0.1
        
        # Duration quality (reasonable length)
        duration_seconds = len(audio_segment) / 1000.0
        if 5 <= duration_seconds <= 300:  # 5 seconds to 5 minutes
            quality_score += 0.1
        
        return min(quality_score, 1.0)
    
    def _calculate_voice_confidence(self, 
                                   transcription: str,
                                   voice_features: Dict[str, Any],
                                   audio_quality: float,
                                   text_analysis: Optional[ScamTextResult]) -> float:
        """Calculate overall confidence in voice scam detection"""
        confidence = 0.0
        
        # Text analysis confidence
        if text_analysis and text_analysis.confidence > 0.3:
            confidence += text_analysis.confidence * 0.6
        
        # Voice pattern matching
        if transcription:
            transcription_lower = transcription.lower()
            pattern_matches = 0
            
            for category, patterns in self.voice_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, transcription_lower):
                        pattern_matches += 1
            
            if pattern_matches > 0:
                confidence += min(pattern_matches * 0.1, 0.3)
        
        # Robocall detection
        if voice_features.get('is_robocall_likely', False):
            confidence += 0.2
        
        # Audio quality factor (poor quality might indicate spoofing)
        if audio_quality < 0.3:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def analyze_live_audio(self, duration_seconds: int = 10) -> VoiceScamResult:
        """Analyze live audio from microphone"""
        if not AUDIO_AVAILABLE:
            raise ImportError("Live audio analysis requires speech_recognition package")
        
        try:
            with sr.Microphone() as source:
                self.recognizer.adjust_for_ambient_noise(source)
                audio = self.recognizer.listen(source, timeout=duration_seconds)
            
            # Convert to audio segment for analysis
            wav_data = io.BytesIO(audio.get_wav_data())
            audio_segment = AudioSegment.from_wav(wav_data)
            
            # Generate hash from audio data
            audio_hash = self._get_audio_hash(audio.get_wav_data())
            
            # Transcribe
            transcription = ""
            try:
                transcription = self.recognizer.recognize_google(audio)
            except:
                pass
            
            # Analyze features
            voice_features = await self._analyze_voice_features(audio_segment)
            audio_quality = self._calculate_audio_quality(audio_segment)
            
            # Text analysis
            text_analysis = None
            if transcription:
                text_analysis = await self.text_analyzer.analyze_text(
                    transcription,
                    source_type="live_call"
                )
            
            confidence = self._calculate_voice_confidence(
                transcription, voice_features, audio_quality, text_analysis
            )
            
            return VoiceScamResult(
                audio_hash=audio_hash,
                transcription=transcription,
                text_analysis=text_analysis,
                voice_features=voice_features,
                audio_quality=audio_quality,
                confidence=confidence,
                detected_at=datetime.now(),
                source_file=None,
                duration_seconds=duration_seconds
            )
            
        except Exception as e:
            raise Exception(f"Live audio analysis failed: {e}")
    
    def get_voice_scam_indicators(self, result: VoiceScamResult) -> List[str]:
        """Get list of voice scam indicators found"""
        indicators = []
        
        if result.voice_features.get('is_robocall_likely', False):
            indicators.append("Robocall characteristics detected")
        
        if result.audio_quality < 0.3:
            indicators.append("Poor audio quality (possible spoofing)")
        
        if result.transcription:
            transcription_lower = result.transcription.lower()
            
            for category, patterns in self.voice_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, transcription_lower):
                        indicators.append(f"Suspicious phrase: '{pattern}' ({category})")
        
        if result.text_analysis and result.text_analysis.suspicious_patterns:
            for pattern in result.text_analysis.suspicious_patterns[:3]:
                indicators.append(f"Text pattern: {pattern}")
        
        return indicators
