# ML-Based Device Classification System

## Overview

This system enhances the network scanner with machine learning capabilities to improve device identification. It addresses common misclassification issues (e.g., routers identified as cameras) by using a combination of features including vendor information, MAC address OUI, operating system, hostname, services, and open ports.

## Features

- **Machine Learning Classification**: Uses a Random Forest classifier with TF-IDF vectorization for text features
- **Confidence Scores**: Provides confidence levels for each classification
- **Fallback Mechanism**: Falls back to rule-based classification when confidence is low
- **Interactive Training**: Allows users to correct misclassifications and add them to the training data
- **Feature Importance**: Shows which features are most important for classification
- **Extensible**: Easily add new device types and training examples

## How to Use

### Training the Classifier

Run the training script to create and train the classifier:

```bash
python train_classifier.py
```

The script provides the following options:

1. **Create Initial Model**: Creates a default model with sample training data
2. **Train with Custom Data**: Add your own device data to improve the model
3. **Test Classifier**: Test the classifier with a device and provide feedback
4. **View Feature Importance**: See which features are most important for classification

### Using the Classifier in the Scanner

The classifier is automatically used by the scanner when analyzing devices. When a device is classified with low confidence, the system will:

1. Show both ML-based and rule-based classifications
2. Ask which classification to use
3. Optionally add the correct classification to the training data

## How It Works

1. **Feature Extraction**: Extracts relevant features from device information
2. **Text Processing**: Uses TF-IDF vectorization to convert text features into numerical values
3. **Classification**: Uses a Random Forest classifier to predict the device type
4. **Confidence Calculation**: Calculates confidence based on prediction probabilities
5. **Fallback**: Falls back to rule-based classification when confidence is low

## Improving the Classifier

To improve the classifier's accuracy:

1. Add more training examples, especially for device types that are often misclassified
2. Correct misclassifications when they occur
3. Add new device types as needed
4. Review feature importance to understand what features are most useful

## Technical Details

- **Model Storage**: Models are stored in `modules/models/device_classifier.pkl`
- **Training Data**: Training data is stored in `modules/models/training_data.json`
- **Algorithm**: Random Forest classifier with 100 estimators
- **Features**: Vendor, MAC OUI, OS, hostname, services, and ports
- **Text Processing**: TF-IDF vectorization with max 1000 features

## Troubleshooting

- If the classifier is not working, check if the model file exists
- If accuracy is low, add more training examples
- If a device type is not recognized, add it using the training script
- If the classifier is not being used, check if the ML classifier module is imported correctly