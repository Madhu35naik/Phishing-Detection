# config.py

MONGO_URI = "mongodb+srv://madhura:Madhura123@cluster0.ikzrg9b.mongodb.net/?appName=Cluster0"
# Change this to your MongoDB connection string if different

MONGO_DATABASE_NAME = "PhishingDB"
MONGO_COLLECTION_NAME = "scan_logs" 

# Log retention policy (e.g., in days)
LOG_RETENTION_DAYS = 30