"""
Train Autoencoder from Custom Dataset (training_data.npy)
Healthcare Cyber-Resilience Platform

This script trains the autoencoder on your custom dataset while
keeping the original normal_data.npy as a fallback.
"""

import torch
import torch.nn as nn
import numpy as np
import os

print("=" * 60)
print("AUTOENCODER TRAINING (CUSTOM DATA)")
print("=" * 60)

# Configuration
CUSTOM_DATA = "training_data.npy"
ORIGINAL_DATA = "normal_data.npy"
MODEL_OUTPUT = "app/model_state.pth"

# Check which data to use
if os.path.exists(CUSTOM_DATA):
    DATA_FILE = CUSTOM_DATA
    print(f"\nUsing CUSTOM data: {CUSTOM_DATA}")
else:
    DATA_FILE = ORIGINAL_DATA
    print(f"\nUsing ORIGINAL data: {ORIGINAL_DATA}")

# Load data
print(f"Loading {DATA_FILE}...")
data = np.load(DATA_FILE)
print(f"Data shape: {data.shape}")

# Get input dimension
input_dim = data.shape[1]
print(f"Input dimension: {input_dim}")

# Define model architecture based on input dimension
class FlexibleAutoencoder(nn.Module):
    """Autoencoder that adapts to input dimension."""
    def __init__(self, input_dim):
        super().__init__()
        
        # Calculate hidden layer sizes
        hidden1 = max(input_dim // 2, 8)
        hidden2 = max(hidden1 // 2, 4)
        
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, hidden2),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(hidden2, hidden1),
            nn.ReLU(),
            nn.Linear(hidden1, input_dim),
            nn.Sigmoid()
        )
        
        print(f"Architecture: {input_dim} -> {hidden1} -> {hidden2} -> {hidden1} -> {input_dim}")
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Create model
print("\nCreating model...")
model = FlexibleAutoencoder(input_dim)

# Training setup
tensor_data = torch.tensor(data, dtype=torch.float32)
criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Training
EPOCHS = 100
print(f"\nTraining for {EPOCHS} epochs...")
print("-" * 50)

batch_size = 64
n_batches = len(tensor_data) // batch_size

for epoch in range(EPOCHS):
    total_loss = 0
    
    # Mini-batch training
    indices = torch.randperm(len(tensor_data))
    for i in range(0, len(tensor_data), batch_size):
        batch_indices = indices[i:i+batch_size]
        batch = tensor_data[batch_indices]
        
        optimizer.zero_grad()
        outputs = model(batch)
        loss = criterion(outputs, batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
    
    avg_loss = total_loss / max(n_batches, 1)
    
    if (epoch + 1) % 10 == 0 or epoch == 0:
        print(f"Epoch [{epoch+1:3d}/{EPOCHS}] - Loss: {avg_loss:.6f}")

print("-" * 50)
print("Training complete!")

# Calculate threshold
print("\nCalculating threshold...")
model.eval()
with torch.no_grad():
    reconstructions = model(tensor_data)
    errors = torch.mean((tensor_data - reconstructions) ** 2, dim=1)
    
mean_error = errors.mean().item()
std_error = errors.std().item()
max_error = errors.max().item()

# Threshold = mean + 2*std (captures 95% of normal traffic)
threshold = mean_error + 2 * std_error

print(f"  Mean error: {mean_error:.6f}")
print(f"  Std error: {std_error:.6f}")  
print(f"  Max error: {max_error:.6f}")
print(f"  Threshold: {threshold:.6f}")

# Save model
print(f"\nSaving model to {MODEL_OUTPUT}...")
torch.save(model.state_dict(), MODEL_OUTPUT)

# Save config for web app
config_file = "app/model_config.txt"
with open(config_file, 'w') as f:
    f.write(f"INPUT_DIM={input_dim}\n")
    f.write(f"THRESHOLD={threshold:.6f}\n")
    f.write(f"DATA_SOURCE={DATA_FILE}\n")

print(f"Saved config to {config_file}")

print("\n" + "=" * 60)
print("SUCCESS!")
print("=" * 60)
print(f"\nModel: {MODEL_OUTPUT}")
print(f"Input Dimension: {input_dim}")
print(f"Threshold: {threshold:.6f}")
print(f"Data Source: {DATA_FILE}")
print("\nRestart the server with .\\start.bat to use the new model!")
print("=" * 60)
