import csv
from collections import defaultdict

def generate_report(input_csv: str, output_file: str):
    """
    Reads the CSV file, filters rows where 'relevant_for_threat_intel' is 'yes',
    and generates a categorized report based on the content.
    """
    # Categories for the report
    categories = {
        "Critical – Vulnerabilities": [],
        "Malware/Ransomware Threats": []
    }

    # Keywords to classify content
    vulnerability_keywords = ["vulnerability", "CVE", "RCE", "zero-day", "exploit", "critical"]
    malware_keywords = ["malware", "ransomware", "APT", "stealer", "trojan", "backdoor"]

    # Read the CSV file
    with open(input_csv, 'r', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row.get("relevant_for_threat_intel", "").lower() == "yes":
                title = row.get("title", "No title")
                summary = row.get("summary", "No summary")
                source = row.get("link", "No source")

                # Classify the content
                content = f"{title} {summary}".lower()
                if any(keyword in content for keyword in vulnerability_keywords):
                    categories["Critical – Vulnerabilities"].append(
                        f"{title}\n{summary}\nSource: {source}\n"
                    )
                elif any(keyword in content for keyword in malware_keywords):
                    categories["Malware/Ransomware Threats"].append(
                        f"{title}\n{summary}\nSource: {source}\n"
                    )

    # Write the report to the output file
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for category, entries in categories.items():
            outfile.write(f"{category}\n\n")
            for entry in entries:
                outfile.write(f"{entry}\n")
            outfile.write("\n")

    print(f"Report generated: {output_file}")


# Example usage
input_csv = "threat_intel_analysis.csv"  # Replace with your input CSV file
output_file = "threat_intel_report.txt"  # Replace with your desired output file
generate_report(input_csv, output_file)
