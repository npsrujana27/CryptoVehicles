import pandas as pd
import numpy as np

class VehicleTrust:
    def __init__(self):
        self.vehicles = {}
        self.trust_scores = {}

    def record_packet_forwarding(self, vehicle_id, received, forwarded):
        PFR = forwarded / received if received > 0 else 0
        if vehicle_id not in self.vehicles:
            self.vehicles[vehicle_id] = {"PFR": [], "PFD": []}
        self.vehicles[vehicle_id]["PFR"].append(PFR)
        return PFR

    def record_packet_delay(self, vehicle_id, delays):
        """Corrected PFD Calculation Using Sum of Reciprocals (in milliseconds)"""
        if not delays or all(d == 0 for d in delays):
            PFD = float('inf')  # Avoid division by zero
        else:
            PFD = len(delays) / sum(1 / (d + 1e-6) for d in delays if d > 0)  # Small epsilon to avoid zero division

        self.vehicles[vehicle_id]["PFD"].append(PFD)
        return PFD


    def update_trust_score(self, vehicle_id):
        if vehicle_id not in self.vehicles:
            return 0

        avg_PFR = np.mean(self.vehicles[vehicle_id]["PFR"])
        avg_PFD = np.mean(self.vehicles[vehicle_id]["PFD"])

        trust = 0
        trust += min(100, int(avg_PFR * 100))
        trust_penalty = min(40, avg_PFD / 10)
        trust -= trust_penalty
        trust = max(0, min(100, trust))

        is_malicious = avg_PFR < 0.3 or avg_PFD > 300
        if is_malicious:
            trust = min(trust, 20)

        self.trust_scores[vehicle_id] = trust
        return trust

    def detect_malicious_vehicles(self):
        """Detect vehicles with low PFR or high PFD"""
        malicious_vehicles = []
        for vehicle_id in self.vehicles:
            avg_PFR = np.mean(self.vehicles[vehicle_id]["PFR"])
            avg_PFD = np.mean(self.vehicles[vehicle_id]["PFD"])

            if avg_PFR < 0.3 or avg_PFD > 300:
                malicious_vehicles.append((vehicle_id, avg_PFR, avg_PFD))

        return malicious_vehicles


    def print_trust_scores(self, export_csv=True, filename="trust_scores.csv"):
        print("\n🚗 Vehicle Trust Scores 🚗")
        trust_data = []

        for vehicle_id, trust in self.trust_scores.items():
            avg_PFR = round(np.mean(self.vehicles[vehicle_id]["PFR"]), 3)
            avg_PFD = round(np.mean(self.vehicles[vehicle_id]["PFD"]), 3)
            trust = round(trust, 3)
            trust_data.append([vehicle_id, trust, avg_PFR, avg_PFD])

        df = pd.DataFrame(trust_data, columns=["Vehicle_ID", "Trust Score", "Packet Forwarding Ratio", "Packet Forwarding Delay"])
        print(df.to_string(index=False))

        # Export to CSV if enabled
        if export_csv:
            df.to_csv(filename, index=False)
            print(f"\nTrust scores exported to {filename}")

# Example Usage:
# self.print_trust_scores()

# Load dataset
file_path = "/content/vehicle_dataset (1).csv"
df = pd.read_csv(file_path)

# Initialize trust system
trust_system = VehicleTrust()

# Process dataset
for index, row in df.iterrows():
    vehicle_id = row["vehicle_id"]
    forwarded = row["forwarded"]
    received = row["received"]

    # Convert delay string to list of integers
    delays = list(map(int, row["packet_delays"].strip("[]").split(", "))) if isinstance(row["packet_delays"], str) else []

    trust_system.record_packet_forwarding(vehicle_id, received, forwarded)
    trust_system.record_packet_delay(vehicle_id, delays)
    trust_system.update_trust_score(vehicle_id)

# Print Trust Scores
trust_system.print_trust_scores()

# Detect Malicious Vehicles
malicious_vehicles = trust_system.detect_malicious_vehicles()
print("\n🚨 Malicious Vehicles Detected 🚨")
for vehicle, pfr, pfd in malicious_vehicles:
    print(f"{vehicle}: PFR = {pfr:.2f}, PFD = {pfd:.2f} ms ⚠️")
