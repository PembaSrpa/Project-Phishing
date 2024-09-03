# Provides functions for interacting with the operating system, such as creating, deleting, and renaming files and directories.
import os
# A library for making HTTP requests, allowing you to fetch data from web servers.
import requests
# Enables you to work with ZIP archives, including extracting and creating them.
import zipfile
# Provides functions for compressing and decompressing data using the BZIP2 algorithm.
import bz2
# Offers classes for handling input/output operations, such as reading and writing data from files or strings.
import io
# A powerful data analysis library, providing data structures like DataFrames and Series for efficient manipulation and analysis of tabular data.
import pandas as pd

# Specify the path where you want to save the datasets
save_path = r"C:\Users\Niras\OneDrive\Desktop\Project\Code\Dataset"

# Create the directory if it doesn't exist
os.makedirs(save_path, exist_ok=True)

def download_file(url, filename):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        with open(os.path.join(save_path, filename), 'wb') as f:
            f.write(response.content)
        print(f"Downloaded: {filename}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to download {filename}: {e}")
        return False

def get_phishtank_data():
    url = "http://data.phishtank.com/data/online-valid.csv.bz2"
    response = requests.get(url)
    
    if 'exceeded the request rate limit' in response.text:
        print("PhishTank rate limit exceeded. Using a dummy dataset.")
        return pd.DataFrame({'url': [f'http://phishing-example-{i}.com' for i in range(10000)]})
    
    if response.content[:3] == b'BZh':  # BZ2 magic number
        with bz2.open(io.BytesIO(response.content), 'rt') as f:
            df = pd.read_csv(f)
    else:
        print("Warning: The downloaded file is not in bz2 format.")
        print("First few bytes:", response.content[:20])
        print("Attempting to read as plain CSV...")
        try:
            df = pd.read_csv(io.StringIO(response.text), encoding="latin-1")  # Replace with "cp1252" if needed
        except UnicodeDecodeError:
            print("Failed to decode with latin-1. Trying default encoding...")
            df = pd.read_csv(io.StringIO(response.text))
    
    if 'url' not in df.columns:
        print("'url' column not found. Using the first column as URL.")
        df = df.rename(columns={df.columns[0]: 'url'})
    
    return df

# Download Tranco list
tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
tranco_zip = os.path.join(save_path, "tranco_top-1m.csv.zip")
if download_file(tranco_url, "tranco_top-1m.csv.zip"):
    # Extract Tranco CSV
    with zipfile.ZipFile(tranco_zip, 'r') as zip_ref:
        zip_ref.extractall(save_path)
    os.remove(tranco_zip)  # Remove the zip file after extraction
    print("Extracted Tranco CSV")

# Download Majestic Million
majestic_url = "https://downloads.majestic.com/majestic_million.csv"
download_file(majestic_url, "majestic_million.csv")

# Download and process PhishTank dataset
print("Downloading and processing PhishTank data...")
phishtank_df = get_phishtank_data()
phishtank_df.to_csv(os.path.join(save_path, "phishtank_data.csv"), index=False)
print(f"PhishTank data saved to {os.path.join(save_path, 'phishtank_data.csv')}")

print("Dataset download process completed. Check the above messages for any issues.")
