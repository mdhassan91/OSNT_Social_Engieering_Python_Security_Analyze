import os
import pandas as pd
import chardet
import re
from collections import defaultdict
from typing import Dict, List, Any
import json
from fpdf import FPDF


def detect_encoding(file_path: str) -> str:
    """Detect the encoding of a file"""
    with open(file_path, 'rb') as file:
        raw_data = file.read()
        result = chardet.detect(raw_data)
        return result['encoding']


def analyze_column_risk(column_name: str, sample_values: List[Any]) -> Dict[str, Any]:
    """Analyze potential risks in a column using predefined rules."""
    risk_analysis = {
        "risk_level": "Low",
        "info_type": "Unknown",
        "concerns": [],
        "recommendations": []
    }
    
    # Define risk criteria
    risk_criteria = {
        "High": {
            "keywords": ['coord', 'location', 'timezone', 'address'],
            "info_type": "Geographic Data",
            "concerns": [
                "Contains precise location information",
                "Could be used for physical tracking",
                "Reveals user movement patterns"
            ],
            "recommendations": [
                "Anonymize or remove exact coordinates",
                "Use broader geographic areas instead",
                "Implement geographic data masking"
            ]
        },
        "Medium": {
            "keywords": ['gender', 'name', 'profile', 'description'],
            "info_type": "Personal Information",
            "concerns": [
                "Contains demographic information",
                "Could be used for profiling",
                "May contain personally identifiable information"
            ],
            "recommendations": [
                "Remove or anonymize personal identifiers",
                "Implement data minimization",
                "Consider aggregating demographic data"
            ]
        },
    }

    # Check against criteria
    for level, criteria in risk_criteria.items():
        if any(term in column_name.lower() for term in criteria["keywords"]):
            risk_analysis["risk_level"] = level
            risk_analysis["info_type"] = criteria["info_type"]
            risk_analysis["concerns"] = criteria["concerns"]
            risk_analysis["recommendations"] = criteria["recommendations"]
            break

    # Special handling for specific cases
    if 'coord' in column_name.lower() and any(isinstance(x, (float, int)) for x in sample_values):
        risk_analysis["risk_level"] = "Critical"
        risk_analysis["concerns"].append("Contains exact GPS coordinates")
        risk_analysis["recommendations"].append("Replace with geohashed or area-level data")
    
    if 'description' in column_name.lower():
        risk_analysis["risk_level"] = "High"
        risk_analysis["concerns"].extend([
            "May contain personal narratives",
            "Could include contact information",
            "Potential for indirect identification"
        ])
        risk_analysis["recommendations"].extend([
            "Implement text anonymization",
            "Remove or redact sensitive information",
            "Consider removing full descriptions"
        ])
    
    return risk_analysis


def export_to_csv(findings: Dict[str, List[Dict]], output_path: str):
    """Export findings to a CSV file."""
    rows = []
    for category, items in findings.items():
        for item in items:
            row = {
                "Category": category,
                "Column": item["column"],
                "Risk Level": item["analysis"]["risk_level"],
                "Information Type": item["analysis"]["info_type"],
                "Concerns": "; ".join(item["analysis"]["concerns"]),
                "Recommendations": "; ".join(item["analysis"]["recommendations"]),
                "Sample Values": ", ".join(map(str, item["samples"]))
            }
            rows.append(row)
    df = pd.DataFrame(rows)
    df.to_csv(output_path, index=False)


def export_to_pdf(findings: Dict[str, List[Dict]], output_path: str):
    """Export findings to a PDF report."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Data Security Risk Analysis Report", ln=True, align='C')

    for category, items in findings.items():
        pdf.ln(10)
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, f"Category: {category}", ln=True)
        pdf.set_font("Arial", size=10)

        for item in items:
            pdf.cell(0, 10, f"Column: {item['column']}", ln=True)
            pdf.cell(0, 10, f"Risk Level: {item['analysis']['risk_level']}", ln=True)
            pdf.cell(0, 10, f"Information Type: {item['analysis']['info_type']}", ln=True)
            pdf.cell(0, 10, "Concerns:", ln=True)
            for concern in item["analysis"]["concerns"]:
                pdf.cell(0, 10, f"- {concern}", ln=True)
            pdf.cell(0, 10, "Recommendations:", ln=True)
            for recommendation in item["analysis"]["recommendations"]:
                pdf.cell(0, 10, f"- {recommendation}", ln=True)
            pdf.cell(0, 10, "Sample Values:", ln=True)
            pdf.cell(0, 10, f"{', '.join(map(str, item['samples']))}", ln=True)
            pdf.ln(5)
    
    pdf.output(output_path)


def analyze_security_risks(csv_path: str, export_csv_path: str, export_pdf_path: str):
    """Analyze CSV file for potential security risks and export findings."""
    if not os.path.exists(csv_path):
        print("Error: File does not exist.")
        return
    
    # Detect encoding
    encoding = detect_encoding(csv_path)
    df = pd.read_csv(csv_path, encoding=encoding)
    
    findings = defaultdict(list)
    patterns = {
        'Locations': r'location|coord|timezone|address',
        'Personal Info': r'name|gender|profile|description',
        'Timestamps': r'created|time|date',
        'IDs': r'id|uuid|guid',
        'Social Media': r'tweet|retweet|profile|sidebar|user',
        'URLs/Links': r'link|url|href',
    }
    
    # Analyze columns
    for category, pattern in patterns.items():
        matching_cols = [col for col in df.columns if re.search(pattern, col.lower())]
        for col in matching_cols:
            samples = df[col].dropna().unique()[:3]
            analysis = analyze_column_risk(col, samples)
            findings[category].append({
                "column": col,
                "samples": samples,
                "analysis": analysis
            })
    
    # Export findings
    export_to_csv(findings, export_csv_path)
    export_to_pdf(findings, export_pdf_path)
    print(f"Analysis complete. Results saved to {export_csv_path} and {export_pdf_path}.")


if __name__ == "__main__":
    csv_path = "gender-classifier-DFE-791531.csv"
    export_csv_path = "security_risk_analysis.csv"
    export_pdf_path = "security_risk_analysis.pdf"
    analyze_security_risks(csv_path, export_csv_path, export_pdf_path)
