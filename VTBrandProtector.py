import os
import json
import logging
import argparse
import vt
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize and create a VirusTotal client
def create_vt_client():
    load_dotenv()
    api_key = os.getenv('VT_API_KEY')
    if api_key is None:
        logging.error("API key is not set in environment variables.")
        return None
    try:
        client = vt.Client(api_key)
        logging.info("VirusTotal client successfully created.")
        return client
    except Exception as e:
        logging.error(f"Failed to create VirusTotal client: {e}")
        return None

# Search VirusTotal with the given query and return the results
def search_virus_total(client, query, limit=50):
    if client is not None:
        try:
            iterator = client.iterator("/intelligence/search", params={"query": " ".join(query)}, limit=limit)
            return iterator
        except Exception as e:
            logging.error(f"Error searching VirusTotal: {e}")
            return None
    return None

def main(file_path):
    try:
        # Load JSON data from file
        with open(file_path, 'r') as f:
            entities = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load or parse JSON data: {e}")
        return

    if entities:
        with create_vt_client() as client:
            if client is not None:
                for entity in entities:
                    logging.info(f"Processing entity: {entity['name']}")
                    # Define queries
                    url_query = [f"entity:url content:\"{entity['name']}\""]
                    domain_query = [f"entity:domain main_icon_dhash:{entity['domain_dhash']}"]
                    typosquatted_query = [f"entity:domain fuzzy_domain:\"{entity['legitimateDomain']}\" NOT parent_domain:\"{entity['legitimateDomain']}\""]

                    # Perform URL query search
                    url_results = search_virus_total(client, url_query)
                    if url_results:
                        for result in url_results:
                            logging.info(result)

                    # Perform domain dhash query search
                    domain_results = search_virus_total(client, domain_query)
                    if domain_results:
                        for result in domain_results:
                            logging.info(result)

                    # Perform typosquatted domain query search
                    typosquatted_domain_results = search_virus_total(client, typosquatted_query)
                    if typosquatted_domain_results:
                        for result in typosquatted_domain_results:
                            logging.info(result)
            else:
                logging.error("VirusTotal client could not be created. Exiting...")
                return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search VirusTotal based on JSON defined queries.")
    parser.add_argument("file_path", type=str, help="Path to the JSON file containing the queries.")
    args = parser.parse_args()
    main(args.file_path)
