"""
Generate New Testing Dataset for Autoencoder Training
Healthcare Cyber-Resilience Platform

Creates a synthetic dataset of "normal" healthcare API traffic patterns.
"""

import numpy as np
import os

# Set random seed for reproducibility
np.random.seed(42)

# Number of samples in training data
NUM_SAMPLES = 1000

# Feature dimensions (10 features per sample)
# Features represent normalized API request characteristics:
# 1. Path hash (0-1)
# 2. Method score (GET=0.2, POST=0.4, PUT=0.6, DELETE=0.8)
# 3. Status code normalized (200=0.2, 201=0.25, 400=0.6, 500=1.0)
# 4. User-agent score (normal browser=0.2, mobile=0.3, bot=0.8)
# 5. Request size normalized (0-1)
# 6. Response time normalized (0-1)
# 7. Time of day (0-1, normalized hour)
# 8. Day of week (0-1, normalized)
# 9. Request frequency (requests per minute, normalized)
# 10. Error rate (0-1)

def generate_normal_traffic(n_samples):
    """
    Generate synthetic normal healthcare API traffic.
    Normal traffic has predictable patterns.
    """
    data = np.zeros((n_samples, 10))
    
    for i in range(n_samples):
        # Feature 1: Path hash - normal traffic hits common endpoints
        # Common paths: /api/v1/patients, /api/v1/vitals, /api/v1/appointments
        data[i, 0] = np.random.choice([0.1, 0.2, 0.3, 0.4, 0.5]) + np.random.uniform(-0.05, 0.05)
        
        # Feature 2: Method - normal is mostly GET and POST
        data[i, 1] = np.random.choice([0.2, 0.4], p=[0.7, 0.3]) + np.random.uniform(-0.05, 0.05)
        
        # Feature 3: Status code - normal traffic has mostly 200s
        data[i, 2] = np.random.choice([0.2, 0.25, 0.3], p=[0.85, 0.10, 0.05]) + np.random.uniform(-0.02, 0.02)
        
        # Feature 4: User-agent - normal is browsers and mobile apps
        data[i, 3] = np.random.choice([0.2, 0.3, 0.35], p=[0.5, 0.4, 0.1]) + np.random.uniform(-0.05, 0.05)
        
        # Feature 5: Request size - normal is small to medium
        data[i, 4] = np.random.uniform(0.1, 0.3)
        
        # Feature 6: Response time - normal is fast (low values)
        data[i, 5] = np.random.uniform(0.1, 0.25)
        
        # Feature 7: Time of day - normal is during business hours (0.3-0.7)
        data[i, 6] = np.random.uniform(0.3, 0.7) + np.random.uniform(-0.1, 0.1)
        
        # Feature 8: Day of week - normal is weekdays (0.2-0.7)
        data[i, 7] = np.random.uniform(0.2, 0.7)
        
        # Feature 9: Request frequency - normal is moderate (not too fast)
        data[i, 8] = np.random.uniform(0.1, 0.3)
        
        # Feature 10: Error rate - normal has very low errors
        data[i, 9] = np.random.uniform(0.0, 0.1)
    
    # Clip all values to [0, 1]
    data = np.clip(data, 0, 1)
    
    return data

# Generate the dataset
print("=" * 50)
print("GENERATING NEW TESTING DATASET")
print("=" * 50)
print(f"Samples: {NUM_SAMPLES}")
print(f"Features: 10")

normal_data = generate_normal_traffic(NUM_SAMPLES)

print("\nDataset Statistics:")
print(f"  Shape: {normal_data.shape}")
print(f"  Min: {normal_data.min():.4f}")
print(f"  Max: {normal_data.max():.4f}")
print(f"  Mean: {normal_data.mean():.4f}")
print(f"  Std: {normal_data.std():.4f}")

# Save to file
output_path = "normal_data.npy"
np.save(output_path, normal_data)
print(f"\n✅ Saved to: {output_path}")
print(f"   File size: {os.path.getsize(output_path)} bytes")

print("\n" + "=" * 50)
print("BACKUP INFO:")
print("=" * 50)
print("Old dataset saved as: normal_data_backup.npy")
print("To restore old dataset:")
print("  1. Delete current normal_data.npy")
print("  2. Rename normal_data_backup.npy to normal_data.npy")
print("=" * 50)
