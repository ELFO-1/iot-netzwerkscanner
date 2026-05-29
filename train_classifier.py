#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Training script for the ML-based device classifier
Use this script to train the classifier with your own device data

Author: ELFO
Version: 4.0
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the current directory to the path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the classifier
try:
    from modules.ml_classifier import DeviceClassifier, create_default_model
    from modules.utils import Color
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)


def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f"{Color.GREEN}{title}{Color.RESET}".center(60))
    print("=" * 60 + "\n")


def add_custom_device():
    """Add a custom device to the training data"""
    print_header("Add Custom Device")
    
    device_info = {}
    
    # Get device information
    device_info['ip'] = input(f"{Color.YELLOW}IP Address: {Color.RESET}")
    device_info['mac'] = input(f"{Color.YELLOW}MAC Address (optional): {Color.RESET}")
    device_info['vendor'] = input(f"{Color.YELLOW}Vendor (e.g., TP-Link, Cisco): {Color.RESET}")
    device_info['hostname'] = input(f"{Color.YELLOW}Hostname (optional): {Color.RESET}")
    device_info['os'] = input(f"{Color.YELLOW}Operating System (optional): {Color.RESET}")
    
    # Get services information
    print(f"\n{Color.YELLOW}Enter services (one per line, empty line to finish):{Color.RESET}")
    print(f"{Color.BLUE}Format: Port 80: http, Port 443: https, etc.{Color.RESET}")
    
    services = []
    while True:
        service = input()
        if not service:
            break
        services.append(service)
    
    device_info['services'] = '\n'.join(services)
    
    # Get the correct device type
    classifier = DeviceClassifier()
    device_types = classifier.get_device_types()
    
    print(f"\n{Color.YELLOW}Available device types:{Color.RESET}")
    for i, device_type in enumerate(device_types):
        print(f"  {i+1}. {device_type}")
    print(f"  {len(device_types)+1}. Other (enter custom type)")
    
    while True:
        try:
            choice = int(input(f"\n{Color.YELLOW}Select device type (number): {Color.RESET}"))
            if 1 <= choice <= len(device_types):
                device_type = device_types[choice-1]
                break
            elif choice == len(device_types)+1:
                device_type = input(f"\n{Color.YELLOW}Enter custom device type: {Color.RESET}")
                break
            else:
                print(f"{Color.RED}Invalid choice. Please try again.{Color.RESET}")
        except ValueError:
            print(f"{Color.RED}Please enter a number.{Color.RESET}")
    
    # Add to training data
    classifier.add_training_example(device_info, device_type)
    print(f"\n{Color.GREEN}Device added to training data!{Color.RESET}")
    
    return device_info, device_type


def train_with_custom_data():
    """Train the classifier with custom data"""
    print_header("Train with Custom Data")
    
    # Load existing training data if available
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules', 'models')
    training_data_path = os.path.join(model_dir, 'training_data.json')
    
    if os.path.exists(training_data_path):
        with open(training_data_path, 'r') as f:
            data = json.load(f)
        devices = data.get('devices', [])
        labels = data.get('labels', [])
    else:
        devices = []
        labels = []
    
    print(f"{Color.YELLOW}Current training data: {len(devices)} devices{Color.RESET}")
    
    # Add new devices
    while True:
        add_more = input(f"\n{Color.YELLOW}Add another device? (y/n): {Color.RESET}").lower()
        if add_more != 'y':
            break
        
        device, label = add_custom_device()
        devices.append(device)
        labels.append(label)
    
    # Train the model if we have data
    if devices:
        print(f"\n{Color.GREEN}Training model with {len(devices)} devices...{Color.RESET}")
        classifier = DeviceClassifier()
        result = classifier.train(devices, labels)
        
        if 'error' in result:
            print(f"\n{Color.RED}Error training model: {result['error']}{Color.RESET}")
        else:
            print(f"\n{Color.GREEN}Model trained successfully!{Color.RESET}")
            print(f"Accuracy: {result['accuracy']:.2f}")
            print(f"F1 Score: {result['macro_avg_f1']:.2f}")
            print(f"Classes: {result['classes']}")
    else:
        print(f"\n{Color.YELLOW}No training data available.{Color.RESET}")


def test_classifier():
    """Test the classifier with a device"""
    print_header("Test Classifier")
    
    # Get device information
    device_info = {}
    device_info['ip'] = input(f"{Color.YELLOW}IP Address: {Color.RESET}")
    device_info['mac'] = input(f"{Color.YELLOW}MAC Address (optional): {Color.RESET}")
    device_info['vendor'] = input(f"{Color.YELLOW}Vendor (e.g., TP-Link, Cisco): {Color.RESET}")
    device_info['hostname'] = input(f"{Color.YELLOW}Hostname (optional): {Color.RESET}")
    device_info['os'] = input(f"{Color.YELLOW}Operating System (optional): {Color.RESET}")
    
    # Get services information
    print(f"\n{Color.YELLOW}Enter services (one per line, empty line to finish):{Color.RESET}")
    print(f"{Color.BLUE}Format: Port 80: http, Port 443: https, etc.{Color.RESET}")
    
    services = []
    while True:
        service = input()
        if not service:
            break
        services.append(service)
    
    device_info['services'] = '\n'.join(services)
    
    # Classify the device
    classifier = DeviceClassifier()
    device_type, confidence = classifier.predict(device_info)
    
    print(f"\n{Color.GREEN}Classification Result:{Color.RESET}")
    print(f"Device Type: {device_type}")
    print(f"Confidence: {confidence:.2f}")
    
    # Ask if the classification is correct
    is_correct = input(f"\n{Color.YELLOW}Is this classification correct? (y/n): {Color.RESET}").lower() == 'y'
    
    if not is_correct:
        # Get the correct device type
        device_types = classifier.get_device_types()
        
        print(f"\n{Color.YELLOW}Available device types:{Color.RESET}")
        for i, dt in enumerate(device_types):
            print(f"  {i+1}. {dt}")
        print(f"  {len(device_types)+1}. Other (enter custom type)")
        
        while True:
            try:
                choice = int(input(f"\n{Color.YELLOW}Select correct device type (number): {Color.RESET}"))
                if 1 <= choice <= len(device_types):
                    correct_type = device_types[choice-1]
                    break
                elif choice == len(device_types)+1:
                    correct_type = input(f"\n{Color.YELLOW}Enter custom device type: {Color.RESET}")
                    classifier.add_device_type(correct_type)
                    break
                else:
                    print(f"{Color.RED}Invalid choice. Please try again.{Color.RESET}")
            except ValueError:
                print(f"{Color.RED}Please enter a number.{Color.RESET}")
        
        # Add to training data
        classifier.add_training_example(device_info, correct_type)
        print(f"\n{Color.GREEN}Device added to training data with correct type: {correct_type}{Color.RESET}")
    else:
        print(f"\n{Color.GREEN}Great! The classifier is working correctly.{Color.RESET}")


def view_feature_importance():
    """View the most important features for classification"""
    print_header("Feature Importance")
    
    classifier = DeviceClassifier()
    importance = classifier.get_feature_importance(top_n=20)
    
    if not importance:
        print(f"{Color.YELLOW}No feature importance data available. Train the model first.{Color.RESET}")
        return
    
    print(f"{Color.GREEN}Top 20 most important features:{Color.RESET}\n")
    for i, (feature, score) in enumerate(importance.items()):
        print(f"{i+1:2d}. {feature:<30} {score:.4f}")


def create_initial_model():
    """Create an initial model with default data"""
    print_header("Create Initial Model")
    
    print(f"{Color.YELLOW}Creating initial model with default data...{Color.RESET}")
    create_default_model()
    print(f"\n{Color.GREEN}Initial model created successfully!{Color.RESET}")
    print(f"\n{Color.YELLOW}You can now train it with your own data.{Color.RESET}")


def main_menu():
    """Display the main menu"""
    while True:
        clear_screen()
        print_header("ML Device Classifier Training Tool")
        
        print(f"{Color.YELLOW}1. Create Initial Model{Color.RESET}")
        print(f"{Color.YELLOW}2. Train with Custom Data{Color.RESET}")
        print(f"{Color.YELLOW}3. Test Classifier{Color.RESET}")
        print(f"{Color.YELLOW}4. View Feature Importance{Color.RESET}")
        print(f"{Color.YELLOW}5. Exit{Color.RESET}")
        
        choice = input(f"\n{Color.GREEN}Select an option: {Color.RESET}")
        
        if choice == '1':
            create_initial_model()
        elif choice == '2':
            train_with_custom_data()
        elif choice == '3':
            test_classifier()
        elif choice == '4':
            view_feature_importance()
        elif choice == '5':
            print(f"\n{Color.GREEN}Goodbye!{Color.RESET}")
            break
        else:
            print(f"\n{Color.RED}Invalid choice. Please try again.{Color.RESET}")
        
        input(f"\n{Color.YELLOW}Press Enter to continue...{Color.RESET}")


if __name__ == "__main__":
    main_menu()