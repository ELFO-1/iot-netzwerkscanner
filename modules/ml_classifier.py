#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Machine Learning Classifier for IoT Device Identification

This module provides a machine learning-based approach to identify IoT devices
based on their network characteristics, vendor information, and services.

Author: ELFO
Version: 4.0
"""

import os
import json
import pickle
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Union
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class DeviceClassifier:
    """Machine Learning Classifier for IoT Device Identification"""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the classifier
        
        Args:
            model_path: Path to the saved model file. If None, uses default path.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Set up model directory
        self.model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Set model path
        self.model_path = model_path or os.path.join(self.model_dir, 'device_classifier.pkl')
        self.training_data_path = os.path.join(self.model_dir, 'training_data.json')
        
        # Initialize model and vectorizers
        self.model = None
        self.feature_names = []
        self.device_types = []
        self.feature_importance = {}
        
        # Load model if it exists
        self._load_model()
    
    def _load_model(self) -> None:
        """Load the model from disk if it exists"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.model = model_data.get('model')
                self.feature_names = model_data.get('feature_names', [])
                self.device_types = model_data.get('device_types', [])
                self.feature_importance = model_data.get('feature_importance', {})
                
                self.logger.info(f"Model loaded from {self.model_path}")
                self.logger.info(f"Available device types: {self.device_types}")
            else:
                self.logger.warning(f"No model found at {self.model_path}")
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
    
    def _save_model(self) -> None:
        """Save the model to disk"""
        try:
            if self.model is not None:
                model_data = {
                    'model': self.model,
                    'feature_names': self.feature_names,
                    'device_types': self.device_types,
                    'feature_importance': self.feature_importance
                }
                
                with open(self.model_path, 'wb') as f:
                    pickle.dump(model_data, f)
                
                self.logger.info(f"Model saved to {self.model_path}")
            else:
                self.logger.warning("No model to save")
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
    
    def _extract_features(self, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from device information
        
        Args:
            device_info: Dictionary containing device information
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Extract vendor information
        vendor = device_info.get('vendor', '').lower()
        features['vendor'] = vendor
        
        # Extract MAC OUI (first 6 characters of MAC address)
        mac = device_info.get('mac', '').lower().replace(':', '').replace('-', '')
        if mac and len(mac) >= 6:
            features['mac_oui'] = mac[:6]
        else:
            features['mac_oui'] = ''
        
        # Extract OS information
        os_info = device_info.get('os', '').lower()
        features['os'] = os_info
        
        # Extract hostname
        hostname = device_info.get('hostname', '').lower()
        features['hostname'] = hostname
        
        # Extract services
        services = device_info.get('services', '').lower()
        features['services'] = services
        
        # Extract open ports
        ports = []
        for line in services.split('\n'):
            if ':' in line:
                port = line.split(':')[0].strip()
                if port.isdigit():
                    ports.append(port)
        
        features['ports'] = ' '.join(ports)
        
        return features
    
    def train(self, devices: List[Dict[str, Any]], labels: List[str]) -> Dict[str, Any]:
        """Train the classifier with device data
        
        Args:
            devices: List of device information dictionaries
            labels: List of device type labels
            
        Returns:
            Dictionary with training results
        """
        try:
            if not devices or not labels or len(devices) != len(labels):
                return {'error': 'Invalid training data'}
            
            # Extract features from devices
            features = [self._extract_features(device) for device in devices]
            
            # Create a DataFrame for easier processing
            df = pd.DataFrame(features)
            
            # Add labels
            df['label'] = labels
            
            # Update device types
            self.device_types = sorted(list(set(labels)))
            
            # Split into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(
                df.drop('label', axis=1),
                df['label'],
                test_size=0.2,
                random_state=42
            )
            
            # Create feature processing pipeline
            text_features = ['vendor', 'os', 'hostname', 'services', 'mac_oui', 'ports']
            
            # Create preprocessor
            preprocessor = ColumnTransformer(
                transformers=[
                    ('text', TfidfVectorizer(max_features=1000), text_features)
                ],
                remainder='drop'
            )
            
            # Create pipeline with preprocessor and classifier
            self.model = Pipeline([
                ('preprocessor', preprocessor),
                ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
            ])
            
            # Train the model
            self.model.fit(X_train, y_train)
            
            # Make predictions on test set
            y_pred = self.model.predict(X_test)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            macro_avg_f1 = f1_score(y_test, y_pred, average='macro')
            report = classification_report(y_test, y_pred, output_dict=True)
            
            # Get feature names
            tfidf = self.model.named_steps['preprocessor'].transformers_[0][1]
            self.feature_names = tfidf.get_feature_names_out()
            
            # Get feature importance
            importances = self.model.named_steps['classifier'].feature_importances_
            self.feature_importance = {}
            for i, importance in enumerate(importances):
                if i < len(self.feature_names):
                    self.feature_importance[self.feature_names[i]] = float(importance)
            
            # Sort feature importance
            self.feature_importance = dict(sorted(
                self.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            ))
            
            # Save model and training data
            self._save_model()
            self._save_training_data(devices, labels)
            
            return {
                'accuracy': accuracy,
                'macro_avg_f1': macro_avg_f1,
                'report': report,
                'classes': self.device_types
            }
        
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            return {'error': str(e)}
    
    def predict(self, device_info: Dict[str, Any]) -> Tuple[str, float]:
        """Predict the device type for a given device
        
        Args:
            device_info: Dictionary containing device information
            
        Returns:
            Tuple of (predicted_device_type, confidence)
        """
        try:
            if self.model is None:
                self.logger.warning("No model loaded, returning 'Unknown'")
                return "Unknown", 0.0
            
            # Extract features
            features = self._extract_features(device_info)
            
            # Create DataFrame
            df = pd.DataFrame([features])
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            
            # Get prediction probabilities
            proba = self.model.predict_proba(df)[0]
            confidence = max(proba)
            
            return prediction, confidence
        
        except Exception as e:
            self.logger.error(f"Error predicting device type: {str(e)}")
            return "Unknown", 0.0
    
    def get_feature_importance(self, top_n: Optional[int] = None) -> Dict[str, float]:
        """Get the feature importance
        
        Args:
            top_n: Number of top features to return. If None, returns all.
            
        Returns:
            Dictionary of feature names and importance scores
        """
        if not self.feature_importance:
            return {}
        
        if top_n is not None:
            return dict(list(self.feature_importance.items())[:top_n])
        
        return self.feature_importance
    
    def add_training_example(self, device_info: Dict[str, Any], device_type: str) -> bool:
        """Add a new training example and retrain the model
        
        Args:
            device_info: Dictionary containing device information
            device_type: The correct device type
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load existing training data
            devices, labels = self._load_training_data()
            
            # Add new example
            devices.append(device_info)
            labels.append(device_type)
            
            # Save training data
            self._save_training_data(devices, labels)
            
            # Retrain the model
            self.train(devices, labels)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding training example: {str(e)}")
            return False
    
    def _load_training_data(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Load training data from disk
        
        Returns:
            Tuple of (devices, labels)
        """
        try:
            if os.path.exists(self.training_data_path):
                with open(self.training_data_path, 'r') as f:
                    data = json.load(f)
                
                devices = data.get('devices', [])
                labels = data.get('labels', [])
                
                return devices, labels
            else:
                return [], []
        
        except Exception as e:
            self.logger.error(f"Error loading training data: {str(e)}")
            return [], []
    
    def _save_training_data(self, devices: List[Dict[str, Any]], labels: List[str]) -> None:
        """Save training data to disk
        
        Args:
            devices: List of device information dictionaries
            labels: List of device type labels
        """
        try:
            data = {
                'devices': devices,
                'labels': labels
            }
            
            with open(self.training_data_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Training data saved to {self.training_data_path}")
        
        except Exception as e:
            self.logger.error(f"Error saving training data: {str(e)}")
    
    def get_device_types(self) -> List[str]:
        """Get the list of known device types
        
        Returns:
            List of device types
        """
        return self.device_types
    
    def add_device_type(self, device_type: str) -> None:
        """Add a new device type to the list
        
        Args:
            device_type: The new device type
        """
        if device_type not in self.device_types:
            self.device_types.append(device_type)
            self.device_types.sort()
            self._save_model()


def create_default_model() -> None:
    """Create and save a default model with sample training data"""
    # Sample training data
    devices = [
        {
            'ip': '192.168.1.1',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'vendor': 'TP-Link',
            'hostname': 'router.home',
            'os': 'Linux',
            'services': 'Port 80: http\nPort 443: https\nPort 53: dns\nPort 22: ssh'
        },
        {
            'ip': '192.168.1.2',
            'mac': '11:22:33:44:55:66',
            'vendor': 'Cisco',
            'hostname': 'switch.home',
            'os': 'IOS',
            'services': 'Port 22: ssh\nPort 23: telnet\nPort 80: http\nPort 443: https'
        },
        {
            'ip': '192.168.1.3',
            'mac': 'aa:11:bb:22:cc:33',
            'vendor': 'Hikvision',
            'hostname': 'camera1',
            'os': 'Embedded',
            'services': 'Port 80: http\nPort 554: rtsp\nPort 8000: onvif'
        },
        {
            'ip': '192.168.1.4',
            'mac': 'dd:ee:ff:00:11:22',
            'vendor': 'HP',
            'hostname': 'printer',
            'os': 'Embedded',
            'services': 'Port 80: http\nPort 443: https\nPort 631: ipp\nPort 9100: jetdirect'
        },
        {
            'ip': '192.168.1.5',
            'mac': '33:44:55:66:77:88',
            'vendor': 'Samsung',
            'hostname': 'smarttv',
            'os': 'Tizen',
            'services': 'Port 80: http\nPort 443: https\nPort 8001: dlna\nPort 8080: upnp'
        },
        {
            'ip': '192.168.1.6',
            'mac': '99:88:77:66:55:44',
            'vendor': 'Raspberry Pi',
            'hostname': 'rpi',
            'os': 'Linux',
            'services': 'Port 22: ssh\nPort 80: http\nPort 1883: mqtt'
        },
        {
            'ip': '192.168.1.7',
            'mac': 'ab:cd:ef:12:34:56',
            'vendor': 'Dahua',
            'hostname': 'camera2',
            'os': 'Embedded',
            'services': 'Port 80: http\nPort 443: https\nPort 554: rtsp'
        },
        {
            'ip': '192.168.1.8',
            'mac': '78:90:ab:cd:ef:12',
            'vendor': 'Ubiquiti',
            'hostname': 'ap',
            'os': 'Linux',
            'services': 'Port 22: ssh\nPort 80: http\nPort 443: https'
        },
        {
            'ip': '192.168.1.9',
            'mac': '34:56:78:90:ab:cd',
            'vendor': 'Sonos',
            'hostname': 'speaker',
            'os': 'Embedded',
            'services': 'Port 80: http\nPort 443: https\nPort 1400: upnp'
        },
        {
            'ip': '192.168.1.10',
            'mac': 'ef:12:34:56:78:90',
            'vendor': 'Philips',
            'hostname': 'hue',
            'os': 'Embedded',
            'services': 'Port 80: http\nPort 443: https\nPort 1900: ssdp'
        }
    ]
    
    labels = [
        'Router/Gateway',
        'Netzwerkgerät',
        'IP-Kamera',
        'Drucker',
        'Media-Gerät',
        'IoT-Sensor',
        'IP-Kamera',
        'Netzwerkgerät',
        'Media-Gerät',
        'IoT-Sensor'
    ]
    
    # Create classifier and train with sample data
    classifier = DeviceClassifier()
    result = classifier.train(devices, labels)
    
    logging.info(f"Default model created with result: {result}")