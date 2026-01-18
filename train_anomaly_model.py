"""
Layer 2 Autoencoder Training Script
Healthcare Cyber-Resilience Platform

Trains an Autoencoder on normal behavior data for anomaly detection.
"""

import numpy as np
import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

# ============================================
# 1. DATA LOADING
# ============================================
print("=" * 50)
print("AUTOENCODER TRAINING SCRIPT")
print("=" * 50)

DATA_FILE = "normal_data.npy"

if os.path.exists(DATA_FILE):
    print(f"\n✅ Loading data from {DATA_FILE}...")
    data = np.load(DATA_FILE)
else:
    print(f"\n⚠️  {DATA_FILE} not found!")
    print("Generating dummy data for testing...")
    # Generate random dummy data: 1000 samples, 64 features
    data = np.random.rand(1000, 64).astype(np.float32)
    print(f"Generated dummy data with shape: {data.shape}")

print(f"Original data shape: {data.shape}")

# ============================================
# 2. PREPROCESSING
# ============================================
# Handle different dimensionalities - flatten to 2D
if len(data.shape) == 1:
    # 1D data - reshape to (samples, 1)
    flat_data = data.reshape(-1, 1)
elif len(data.shape) == 2:
    # Already 2D (samples, features) - use directly
    flat_data = data
elif len(data.shape) == 3:
    # 3D data - flatten to 2D
    flat_data = data.reshape(data.shape[0], -1)
elif len(data.shape) == 4:
    # 4D data (like images) - flatten to 2D
    flat_data = data.reshape(data.shape[0], -1)
else:
    raise ValueError(f"Unexpected data shape: {data.shape}")

# Ensure float32
flat_data = flat_data.astype(np.float32)
print(f"Flattened data shape: {flat_data.shape}")

# Convert to PyTorch FloatTensor
data_tensor = torch.FloatTensor(flat_data)

# ============================================
# 3. MODEL DEFINITION
# ============================================
INPUT_DIM = flat_data.shape[1]
LATENT_DIM = max(8, INPUT_DIM // 4)  # Latent space is 1/4 of input or minimum 8

print(f"\n{'=' * 50}")
print(f"Model Configuration:")
print(f"  INPUT DIMENSION:  {INPUT_DIM}")
print(f"  LATENT DIMENSION: {LATENT_DIM}")
print("=" * 50)


class Autoencoder(nn.Module):
    """
    Standard Autoencoder with Encoder -> Latent -> Decoder architecture.
    Uses ReLU activations and Sigmoid output.
    """
    
    def __init__(self, input_dim, latent_dim):
        super(Autoencoder, self).__init__()
        
        # Calculate intermediate layer size
        hidden_dim = max(latent_dim * 2, input_dim // 2)
        
        # Encoder: Compress input to latent representation
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, latent_dim),
            nn.ReLU()
        )
        
        # Decoder: Reconstruct input from latent representation
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


# ============================================
# 4. TRAINING SETUP
# ============================================
# Create DataLoader
train_dataset = TensorDataset(data_tensor, data_tensor)
train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)

# Initialize model, loss function, and optimizer
model = Autoencoder(INPUT_DIM, LATENT_DIM)
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# ============================================
# 5. TRAINING LOOP
# ============================================
EPOCHS = 50

print(f"\nTraining for {EPOCHS} epochs...")
print("-" * 50)

for epoch in range(EPOCHS):
    model.train()
    total_loss = 0.0
    
    for batch_data, _ in train_loader:
        # Zero gradients
        optimizer.zero_grad()
        
        # Forward pass
        outputs = model(batch_data)
        
        # Calculate reconstruction loss
        loss = criterion(outputs, batch_data)
        
        # Backward pass
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
    
    avg_loss = total_loss / len(train_loader)
    
    # Print progress every 10 epochs
    if (epoch + 1) % 10 == 0 or epoch == 0:
        print(f"Epoch [{epoch+1:3d}/{EPOCHS}] - Loss: {avg_loss:.6f}")

print("-" * 50)
print("✅ Training complete!")

# ============================================
# 6. THRESHOLD CALCULATION
# ============================================
print("\nCalculating anomaly threshold...")

model.eval()
reconstruction_errors = []

with torch.no_grad():
    for batch_data, _ in train_loader:
        outputs = model(batch_data)
        # Calculate per-sample reconstruction error (MSE)
        errors = torch.mean((outputs - batch_data) ** 2, dim=1)
        reconstruction_errors.extend(errors.numpy())

reconstruction_errors = np.array(reconstruction_errors)

# Statistics
mean_error = np.mean(reconstruction_errors)
std_error = np.std(reconstruction_errors)
max_error = np.max(reconstruction_errors)

# Threshold = max error + small buffer (2 standard deviations)
BUFFER = 2 * std_error
threshold = max_error + BUFFER

print(f"  Mean reconstruction error: {mean_error:.6f}")
print(f"  Std reconstruction error:  {std_error:.6f}")
print(f"  Max reconstruction error:  {max_error:.6f}")
print(f"  Buffer (2 * std):          {BUFFER:.6f}")
print(f"  Final Threshold:           {threshold:.6f}")

# ============================================
# 7. SAVE ARTIFACTS
# ============================================
print("\n💾 Saving model artifacts...")

save_dict = {
    'model_state_dict': model.state_dict(),
    'input_dim': INPUT_DIM,
    'latent_dim': LATENT_DIM,
    'threshold': float(threshold)
}

torch.save(save_dict, 'model_state.pth')

print("Saved: model_state.pth")

# ============================================
# 8. SUCCESS MESSAGE
# ============================================
print("\n" + "=" * 50)
print("🎉 TRAINING COMPLETE - SUCCESS!")
print("=" * 50)
print(f"\n📊 INPUT DIMENSION: {INPUT_DIM}")
print(f"🎯 THRESHOLD:       {threshold:.6f}")
print(f"\n💾 Model saved to:  model_state.pth")
print("\nYou can now use these values in your web config!")
print("=" * 50)
