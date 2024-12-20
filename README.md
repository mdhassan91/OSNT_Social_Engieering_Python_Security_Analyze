
# Data Security Risk Analysis Tool

This tool is designed to analyze CSV files for potential security risks in the data, identify sensitive information, and provide recommendations to mitigate risks. It outputs findings in both CSV and PDF formats.

## Features

1. **Encoding Detection**

   - Automatically detects the file encoding using the `chardet` library to ensure compatibility with various data formats.

2. **Column Risk Analysis**

   - Analyzes each column in the CSV file to identify potential security risks using predefined rules.
   - Categorizes data into different risk levels: `Low`, `Medium`, `High`, and `Critical`.
   - Provides specific concerns and actionable recommendations.

3. **Export Findings**

   - Outputs the analysis results to a CSV file for easy review and sharing.
   - Generates a detailed PDF report for presentation and documentation purposes.

4. **Customizable Risk Criteria**

   - Allows modification of risk criteria based on keywords and patterns to match specific use cases.

## Installation

### Prerequisites

- Python 3.7 or higher
- Required Python libraries:
  - `pandas`
  - `chardet`
  - `re`
  - `collections`
  - `fpdf`

### Steps

1. Clone the repository or download the script.
2. Install the required Python libraries using pip:
   ```bash
   pip install pandas chardet fpdf
   ```
3. Place your CSV file in the same directory as the script.

## Usage

1. **Input File**

   - Ensure your CSV file is available in the working directory.
   - Update the script with the name of your input file (e.g., `gender-classifier-DFE-791531.csv`).

2. **Run the Script**
   Execute the script using Python:

   ```bash
   python main.py
   ```

3. **Outputs**

   - A CSV file (`security_risk_analysis.csv`) containing a tabular summary of findings.
   - A PDF file (`security_risk_analysis.pdf`) with a detailed, formatted report.

## How It Works

### 1. Detect File Encoding

The `detect_encoding` function reads the file and uses `chardet` to determine its encoding, ensuring smooth data processing.

### 2. Analyze Columns

The script matches column names against predefined patterns to classify them into categories like `Personal Info`, `Locations`, `Timestamps`, etc. For each column:

- A sample of values is inspected.
- Risks are evaluated based on keywords and value types.
- Concerns and recommendations are generated.

### 3. Export Results

- **CSV Export**: Contains a summary of findings for easy filtering and sorting.
- **PDF Export**: Includes a formatted report with categories, columns, risks, concerns, recommendations, and sample values.

## Example Patterns

The script uses regular expressions to identify sensitive columns based on their names:

| Category      | Pattern    |
| ------------- | ---------- |
| Locations     | `location|coord|timezone|address` |
| Personal Info | `name|gender|profile|description` |
| Timestamps    | `created|time|date` |
| IDs           | `id|uuid|guid` |
| Social Media  | `tweet|retweet|profile|sidebar|user` |
| URLs/Links    | `link|url|href` |

### Risk Levels

- **Critical**: Contains highly sensitive data, such as exact GPS coordinates.
- **High**: May include personal narratives or identifiable information.
- **Medium**: Data that could be used for profiling or demographics.
- **Low**: General data with minimal risk.

## Sample Output

### CSV Output

| Category      | Column      | Risk Level | Information Type     | Concerns                         | Recommendations                 | Sample Values       |
| ------------- | ----------- | ---------- | -------------------- | -------------------------------- | ------------------------------- | ------------------- |
| Personal Info | name        | Medium     | Personal Information | Contains demographic information | Remove or anonymize identifiers | Alice, Bob, Charlie |
| Locations     | coordinates | Critical   | Geographic Data      | Contains exact GPS coordinates   | Replace with area-level data    | 12.34, 56.78        |

### PDF Output

The PDF contains detailed sections for each category with formatted lists of concerns, recommendations, and samples.

## Future Enhancements

- Support for additional file formats (e.g., Excel, JSON).
- Advanced text anonymization for free-text fields.
- Custom risk criteria based on user input.
- Visualization of data categories and risk levels.

## License

This tool is open-source and available under the MIT License.
