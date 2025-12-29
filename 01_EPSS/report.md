```python
import gzip
from io import BytesIO
from time import sleep

import numpy as np
import pandas
import pandas as pd
import os
import requests
import json
import csv
import shutil
from datetime import date, timedelta

from pandas import concat
from sklearn.model_selection import train_test_split
from sklearn.svm import OneClassSVM
```


```python
import seaborn as sns
import matplotlib.pyplot as plt

sns.set_theme(style="whitegrid")
```


```python
from preprocessing_utils import preprocess_NVD_data
```


```python
data_path = 'data'
if not os.path.exists(data_path):
    os.makedirs(data_path)
```

# EPSS data

Download the EPSS data from https://www.first.org/epss/data_stats into `data` folder


```python
base_url = "https://epss.empiricalsecurity.com/epss_scores-"
date_current = str(date.today() - timedelta(days=1))
epss_url = base_url + date_current + ".csv.gz"
epss_filename = "epss_scores-latest.csv"

response = requests.get(epss_url)
if response.status_code != 200:
    print("Error:", response.status_code)
else:
    with open(os.path.join(data_path, epss_filename), "wb") as f:
        f.write(gzip.decompress(response.content))
```


```python
epss_current = pd.read_csv(os.path.join(data_path, epss_filename), header=1)
epss_current  # a Python statement with a variable name at the end of a cell will display its contents below

```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>cve</th>
      <th>epss</th>
      <th>percentile</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>CVE-1999-0001</td>
      <td>0.01151</td>
      <td>0.78020</td>
    </tr>
    <tr>
      <th>1</th>
      <td>CVE-1999-0002</td>
      <td>0.10546</td>
      <td>0.93015</td>
    </tr>
    <tr>
      <th>2</th>
      <td>CVE-1999-0003</td>
      <td>0.89352</td>
      <td>0.99521</td>
    </tr>
    <tr>
      <th>3</th>
      <td>CVE-1999-0004</td>
      <td>0.03037</td>
      <td>0.86249</td>
    </tr>
    <tr>
      <th>4</th>
      <td>CVE-1999-0005</td>
      <td>0.13652</td>
      <td>0.94021</td>
    </tr>
    <tr>
      <th>...</th>
      <td>...</td>
      <td>...</td>
      <td>...</td>
    </tr>
    <tr>
      <th>308071</th>
      <td>CVE-2025-9994</td>
      <td>0.00114</td>
      <td>0.30855</td>
    </tr>
    <tr>
      <th>308072</th>
      <td>CVE-2025-9996</td>
      <td>0.00241</td>
      <td>0.47334</td>
    </tr>
    <tr>
      <th>308073</th>
      <td>CVE-2025-9997</td>
      <td>0.00245</td>
      <td>0.47699</td>
    </tr>
    <tr>
      <th>308074</th>
      <td>CVE-2025-9998</td>
      <td>0.00022</td>
      <td>0.05357</td>
    </tr>
    <tr>
      <th>308075</th>
      <td>CVE-2025-9999</td>
      <td>0.00044</td>
      <td>0.13444</td>
    </tr>
  </tbody>
</table>
<p>308076 rows × 3 columns</p>
</div>



# NVD data


```python
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
date_start_NVD = '2025-09-01T00:00:00.000Z'  # Do NOT change these dates
date_end_NVD = '2025-10-01T00:00:00.000Z'  # Do NOT change these dates
start_index = 0
results_per_page = 1000
total_results = 1

candidate_cves = []
while start_index < total_results:
    params = {
        "pubStartDate": date_start_NVD,
        "pubEndDate": date_end_NVD,
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "noRejected": ""
    }
    response = requests.get(base_url, params=params, timeout=6)
    if response.status_code != 200:
        print("Error:", response.status_code)
        break
    data = response.json()
    total_results = data.get("totalResults", 0)
    candidate_cves.extend(data.get("vulnerabilities", []))
    start_index += results_per_page
    print(start_index)
```

    1000
    2000
    3000
    4000
    5000



```python
# normalize and preprocess data
candidate_cves_df = pd.json_normalize(candidate_cves, record_path=None, sep='.', max_level=None)
candidate_cves_df = preprocess_NVD_data(candidate_cves_df)

# remove vulnerabilities marked as "reject" or "reserved"
candidate_cves_df = candidate_cves_df[
    (candidate_cves_df['cve.vulnStatus'] != 'Reserved') & (candidate_cves_df['cve.vulnStatus'] != 'Reject')]

# merge NVD and EPSS data
candidate_cves_df = candidate_cves_df.merge(epss_current, left_on="cve.id", right_on="cve", how="left")
```

# Exploratory Data Analysis

- Display some examples (e.g., the first two CVE records)


```python
candidate_cves_df.head(2).T
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>0</th>
      <th>1</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>cve.id</th>
      <td>CVE-2025-9751</td>
      <td>CVE-2025-9752</td>
    </tr>
    <tr>
      <th>cve.sourceIdentifier</th>
      <td>cna@vuldb.com</td>
      <td>cna@vuldb.com</td>
    </tr>
    <tr>
      <th>cve.published</th>
      <td>2025-09-01 00:15:34.580000</td>
      <td>2025-09-01 01:15:46.817000</td>
    </tr>
    <tr>
      <th>cve.lastModified</th>
      <td>2025-09-08 14:06:05.217000</td>
      <td>2025-09-04 18:47:25.440000</td>
    </tr>
    <tr>
      <th>cve.vulnStatus</th>
      <td>Analyzed</td>
      <td>Analyzed</td>
    </tr>
    <tr>
      <th>cve.references</th>
      <td>[{'url': 'https://github.com/HAO-RAY/HCR-CVE/i...</td>
      <td>[{'url': 'https://github.com/i-Corner/cve/issu...</td>
    </tr>
    <tr>
      <th>cve.cisaExploitAdd</th>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>cve.cisaActionDue</th>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>cve.cisaRequiredAction</th>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>cve.cisaVulnerabilityName</th>
      <td>NaN</td>
      <td>NaN</td>
    </tr>
    <tr>
      <th>description</th>
      <td>A weakness has been identified in Campcodes On...</td>
      <td>A security vulnerability has been detected in ...</td>
    </tr>
    <tr>
      <th>vulnerable_cpes</th>
      <td>[cpe:2.3:a:campcodes:online_learning_managemen...</td>
      <td>[cpe:2.3:o:dlink:dir-852_firmware:1.00cn_b09:*...</td>
    </tr>
    <tr>
      <th>num_references</th>
      <td>6</td>
      <td>6</td>
    </tr>
    <tr>
      <th>cwe_list</th>
      <td>[CWE-74, CWE-89, CWE-89]</td>
      <td>[CWE-77, CWE-78, CWE-78]</td>
    </tr>
    <tr>
      <th>cvss_version</th>
      <td>3.1</td>
      <td>3.1</td>
    </tr>
    <tr>
      <th>cvss_vectorString</th>
      <td>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td>
    </tr>
    <tr>
      <th>cvss_baseScore</th>
      <td>9.8</td>
      <td>9.8</td>
    </tr>
    <tr>
      <th>cvss_baseSeverity</th>
      <td>CRITICAL</td>
      <td>CRITICAL</td>
    </tr>
    <tr>
      <th>cvss_attackVector</th>
      <td>NETWORK</td>
      <td>NETWORK</td>
    </tr>
    <tr>
      <th>cvss_attackComplexity</th>
      <td>LOW</td>
      <td>LOW</td>
    </tr>
    <tr>
      <th>cvss_privilegesRequired</th>
      <td>NONE</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_userInteraction</th>
      <td>NONE</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_scope</th>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
    </tr>
    <tr>
      <th>cvss_confidentialityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
    <tr>
      <th>cvss_integrityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
    <tr>
      <th>cvss_availabilityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
    <tr>
      <th>cve</th>
      <td>CVE-2025-9751</td>
      <td>CVE-2025-9752</td>
    </tr>
    <tr>
      <th>epss</th>
      <td>0.00039</td>
      <td>0.0055</td>
    </tr>
    <tr>
      <th>percentile</th>
      <td>0.11582</td>
      <td>0.67317</td>
    </tr>
  </tbody>
</table>
</div>



- Show a bar plot with the daily volume of published CVEs


```python
published_counts = candidate_cves_df["cve.published"].dt.date.value_counts().sort_index()

plt.figure(figsize=(12, 5))
sns.barplot(x=published_counts.index, y=published_counts.values, color="k")
plt.xticks(rotation=90)
plt.xlabel("Date")
plt.ylabel("Number of CVEs Published")
plt.title("CVE Publications per Day")
plt.tight_layout()
plt.show()
```


    
![png](LAB_EPSS_files/LAB_EPSS_15_0.png)
    


- Print the description of the last ten published vulnerabilities


```python
for idx, x in enumerate(candidate_cves_df.sort_values('cve.published', ascending=False)[:10].iterrows()):
    print('-' * 100)
    print(x[1]['cve.id'], x[1]['cve.published'])
    print(x[1].description)

```

    ----------------------------------------------------------------------------------------------------
    CVE-2025-61792 2025-09-30 23:15:29.700000
    Quadient DS-700 iQ devices through 2025-09-30 might have a race condition during the quick clicking of (in order) the Question Mark button, the Help Button, the About button, and the Help Button, leading to a transition out of kiosk mode into local administrative access. NOTE: the reporter indicates that the "behavior was observed sporadically" during "limited time on the client site," making it not "possible to gain more information about the specific kiosk mode crashing issue," and the only conclusion was "there appears to be some form of race condition." Accordingly, there can be doubt that a reproducible cybersecurity vulnerability was identified; sporadic software crashes can also be caused by a hardware fault on a single device (for example, transient RAM errors). The reporter also describes a variety of other issues, including initial access via USB because of the absence of a "lock-pick resistant locking solution for the External Controller PC cabinet," which is not a cybersecurity vulnerability (section 4.1.5 of the CNA Operational Rules). Finally, it is unclear whether the device or OS configuration was inappropriate, given that the risks are typically limited to insider threats within the mail operations room of a large company.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-55191 2025-09-30 23:15:29.533000
    Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Versions between 2.1.0 and 2.14.19, 3.2.0-rc1, 3.1.0-rc1 through 3.1.7, and 3.0.0-rc1 through 3.0.18 contain a race condition in the repository credentials handler that can cause the Argo CD server to panic and crash when concurrent operations are performed on the same repository URL. The vulnerability is located in numerous repository related handlers in the util/db/repository_secrets.go file. A valid API token with repositories resource permissions (create, update, or delete actions) is required to trigger the race condition. This vulnerability causes the entire Argo CD server to crash and become unavailable. Attackers can repeatedly and continuously trigger the race condition to maintain a denial-of-service state, disrupting all GitOps operations. This issue is fixed in versions 2.14.20, 3.2.0-rc2, 3.1.8 and 3.0.19.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-43826 2025-09-30 23:15:29.160000
    Stored cross-site scripting (XSS) vulnerabilities in Web Content translation in Liferay Portal 7.4.0 through 7.4.3.112, and older unsupported versions, and Liferay DXP 2023.Q4.0 through 2023.Q4.8, 2023.Q3.1 through 2023.Q3.10, 7.4 GA through update 92, and older unsupported versions allow remote attackers to inject arbitrary web script or HTML via any rich text field in a web content article.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-24525 2025-09-30 23:15:27.970000
    Keysight Ixia Vision has an issue with hardcoded cryptographic material 
    which may allow an attacker to intercept or decrypt payloads sent to the
     device via API calls or user authentication if the end user does not 
    replace the TLS certificate that shipped with the device. Remediation is
     available in Version 6.9.1, released on September 23, 2025.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-56392 2025-09-30 20:15:39.997000
    An Insecure Direct Object Reference (IDOR) in the /dashboard/notes endpoint of Syaqui Collegetivity v1.0.0 allows attackers to impersonate other users and perform arbitrary operations via a crafted POST request.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-36262 2025-09-30 20:15:37.993000
    IBM Planning Analytics Local 2.0.0 through 2.0.106 and 2.1.0 through 2.1.13 
    
    could allow a malicious privileged user to bypass the UI to gain unauthorized access to sensitive information due to the improper validation of input.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-36132 2025-09-30 20:15:37.810000
    IBM Planning Analytics Local 2.0.0 through 2.0.106 and 2.1.0 through 2.1.13 is vulnerable to cross-site scripting. This vulnerability allows an authenticated user to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-10659 2025-09-30 20:15:36.450000
    The Telenium Online Web Application is vulnerable due to a PHP endpoint accessible to unauthenticated network users that improperly handles user-supplied input. This vulnerability occurs due to the insecure termination of a regular expression check within the endpoint. Because the input is not correctly validated or sanitized, an unauthenticated attacker can inject arbitrary operating system commands through a crafted HTTP request, leading to remote code execution on the server in the context of the web application service account.
    ----------------------------------------------------------------------------------------------------
    CVE-2024-55017 2025-09-30 20:15:36.100000
    Account Takeover in Corezoid 6.6.0 in the OAuth2 implementation via an open redirect in the redirect_uri parameter allows attackers to intercept authorization codes and gain unauthorized access to victim accounts.
    ----------------------------------------------------------------------------------------------------
    CVE-2025-56132 2025-09-30 19:15:37.253000
    LiquidFiles filetransfer server is vulnerable to a user enumeration issue in its password reset functionality. The application returns distinguishable responses for valid and invalid email addresses, allowing unauthenticated attackers to determine the existence of user accounts. Version 4.2 introduces user-based lockout mechanisms to mitigate brute-force attacks, user enumeration remains possible by default. In versions prior to 4.2, no such user-level protection is in place, only basic IP-based rate limiting is enforced. This IP-based protection can be bypassed by distributing requests across multiple IPs (e.g., rotating IP or proxies). Effectively bypassing both login and password reset security controls. Successful exploitation allows an attacker to enumerate valid email addresses registered for the application, increasing the risk of follow-up attacks such as password spraying.


We keep track of some information to help us later on.


```python
dropped_columns = []
```

- What is the percentage of CVEs which received a CVSS score?


```python
print(f"{(candidate_cves_df["cvss_baseScore"].count() / len(candidate_cves_df)) * 100:.02f}%")
```

    92.90%


- Report descriptive statistics of CVSS the CVSS base score and/or show its distribution


```python
candidate_cves_df.info()
```

    <class 'pandas.core.frame.DataFrame'>
    RangeIndex: 4322 entries, 0 to 4321
    Data columns (total 29 columns):
     #   Column                      Non-Null Count  Dtype         
    ---  ------                      --------------  -----         
     0   cve.id                      4322 non-null   object        
     1   cve.sourceIdentifier        4322 non-null   object        
     2   cve.published               4322 non-null   datetime64[ns]
     3   cve.lastModified            4322 non-null   datetime64[ns]
     4   cve.vulnStatus              4322 non-null   object        
     5   cve.references              4322 non-null   object        
     6   cve.cisaExploitAdd          14 non-null     object        
     7   cve.cisaActionDue           14 non-null     object        
     8   cve.cisaRequiredAction      14 non-null     object        
     9   cve.cisaVulnerabilityName   14 non-null     object        
     10  description                 4322 non-null   object        
     11  vulnerable_cpes             4322 non-null   object        
     12  num_references              4322 non-null   int64         
     13  cwe_list                    4322 non-null   object        
     14  cvss_version                4015 non-null   object        
     15  cvss_vectorString           4015 non-null   object        
     16  cvss_baseScore              4015 non-null   float64       
     17  cvss_baseSeverity           4015 non-null   category      
     18  cvss_attackVector           4015 non-null   object        
     19  cvss_attackComplexity       4015 non-null   object        
     20  cvss_privilegesRequired     4015 non-null   object        
     21  cvss_userInteraction        4015 non-null   object        
     22  cvss_scope                  4015 non-null   object        
     23  cvss_confidentialityImpact  4015 non-null   object        
     24  cvss_integrityImpact        4015 non-null   object        
     25  cvss_availabilityImpact     4015 non-null   object        
     26  cve                         4322 non-null   object        
     27  epss                        4322 non-null   float64       
     28  percentile                  4322 non-null   float64       
    dtypes: category(1), datetime64[ns](2), float64(3), int64(1), object(22)
    memory usage: 950.0+ KB


We see that feature 6, 7, 8, and 9 have a very small amount of non null values. Therefore, we drop those columns to reduce dimensionality. We also remove all CVEs withtout CVSS data.


```python
dropped_columns = ["cve.cisaExploitAdd", "cve.cisaActionDue", "cve.cisaRequiredAction", "cve.cisaVulnerabilityName"]
candidate_cves_df = candidate_cves_df.drop(columns=dropped_columns).dropna()
```

Here we print some statistics about CVSS base score and we show its distribution related to publication date.


```python
candidate_cves_df["cvss_baseScore"].describe()
```




    count    4015.000000
    mean        6.773898
    std         1.735108
    min         2.200000
    25%         5.500000
    50%         6.500000
    75%         7.800000
    max        10.000000
    Name: cvss_baseScore, dtype: float64




```python
plt.figure(figsize=(12, 5))
sns.displot(x=candidate_cves_df["cvss_baseScore"], color="k")
plt.xticks(rotation=90)
plt.xlabel("CVSS")
plt.ylabel("Count")
plt.title("September 2025")
plt.tight_layout()
plt.show()
```


    <Figure size 1200x500 with 0 Axes>



    
![png](LAB_EPSS_files/LAB_EPSS_28_1.png)
    


It would seem that a relatively high number of CVEs published in september 2025 have a very high CVSS.


```python
plt.figure(figsize=(12, 5))
sns.scatterplot(x=candidate_cves_df["cve.published"], y=candidate_cves_df["cvss_baseScore"], color="k")
plt.xticks(rotation=90)
plt.xlabel("Date")
plt.ylabel("CVSS")
plt.tight_layout()
plt.show()

```


    
![png](LAB_EPSS_files/LAB_EPSS_30_0.png)
    


- #### Report descriptive statistics of EPSS and/or show its distribution

Here we print some statistics about EPSS base score and we show its distribution related to publication date.


```python
candidate_cves_df["epss"].describe()
```




    count    4015.000000
    mean        0.002853
    std         0.030654
    min         0.000020
    25%         0.000190
    50%         0.000410
    75%         0.000570
    max         0.831590
    Name: epss, dtype: float64




```python
plt.figure(figsize=(12, 5))
sns.scatterplot(x=candidate_cves_df["cve.published"], y=candidate_cves_df["epss"], color="k")
plt.xticks(rotation=90)
plt.xlabel("Date")
plt.ylabel("EPSS")
plt.tight_layout()
plt.show()

```


    
![png](LAB_EPSS_files/LAB_EPSS_34_0.png)
    


It is evident that, except for a couple of outliers, on average the EPSS is extremely low.

- #### Produce a scatter plot showing CVSS vs EPSS



```python
plt.figure(figsize=(12, 5))
sns.scatterplot(x=candidate_cves_df["cvss_baseScore"], y=candidate_cves_df["epss"], color="k")
plt.xticks(rotation=90)
plt.xlabel("CVSS")
plt.ylabel("EPSS")
plt.title("September 2025")
plt.tight_layout()
plt.show()
```


    
![png](LAB_EPSS_files/LAB_EPSS_37_0.png)
    


As we can see, the CVSS and EPSS are not really related with each other, even though the only times the EPSS is high enough, it's in the presence of an equally high CVSS. We can further visualize this lack of correlation with a correlation matrix:


```python
plt.figure(figsize=(8, 6))
sns.heatmap(candidate_cves_df[["cvss_baseScore", "epss", "percentile"]].corr(), annot=True, cmap="coolwarm")
plt.title("September 2025")
plt.show()
```


    
![png](LAB_EPSS_files/LAB_EPSS_39_0.png)
    


- #### Extra analysis - Top 20 most frequent vendors


```python
vendor = (
    candidate_cves_df['vulnerable_cpes']
      .astype(str)
      .str.strip()
      .str.split(':')
      .str[3]
      .replace('', np.nan)
)


vendor_counts = (
    vendor
    .dropna()
    .value_counts(dropna=False)
    .rename_axis('vendor')
    .reset_index(name='count')
)

vendor_counts = vendor_counts.sort_values('count', ascending=False)
```


```python
plt.figure(figsize=(12, 6))
top_n = 20
plot_df = vendor_counts.head(top_n)

ax = sns.barplot(data=plot_df, x='vendor', y='count', color='#4C78A8')
ax.set_title('Vendor frequency in vulnerable_cpes', fontsize=14)
ax.set_xlabel('Vendor', fontsize=12)
ax.set_ylabel('Count', fontsize=12)
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()
```


    
![png](LAB_EPSS_files/LAB_EPSS_42_0.png)
    


As per specification, we start by filtering the CVEs with low EPSS (<1%), removing all features we will not need, and turning the remaining ones into categorical.


```python
candidate_cves_df = candidate_cves_df[candidate_cves_df['percentile'] <= 0.01].drop(columns=["epss", "percentile", "cve", "cve.published", "cve.lastModified", "cvss_version", "cve.references", "num_references", "vulnerable_cpes"])
```


```python
cols_to_cat = ["cve.sourceIdentifier", "cve.vulnStatus", "cvss_vectorString", "cvss_baseSeverity", "cvss_attackVector",
               "cvss_attackComplexity", "cvss_privilegesRequired", "cvss_userInteraction", "cvss_scope",
               "cvss_confidentialityImpact", "cvss_integrityImpact",
               "cvss_availabilityImpact"]
candidate_cves_df[cols_to_cat] = candidate_cves_df[cols_to_cat].astype('category')
candidate_cves_df.info()
# save the final dataframe
candidate_cves_df.to_csv(os.path.join(data_path, "candidate_cves_df.csv"))
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 167 entries, 20 to 4304
    Data columns (total 16 columns):
     #   Column                      Non-Null Count  Dtype   
    ---  ------                      --------------  -----   
     0   cve.id                      167 non-null    object  
     1   cve.sourceIdentifier        167 non-null    category
     2   cve.vulnStatus              167 non-null    category
     3   description                 167 non-null    object  
     4   cwe_list                    167 non-null    object  
     5   cvss_vectorString           167 non-null    category
     6   cvss_baseScore              167 non-null    float64 
     7   cvss_baseSeverity           167 non-null    category
     8   cvss_attackVector           167 non-null    category
     9   cvss_attackComplexity       167 non-null    category
     10  cvss_privilegesRequired     167 non-null    category
     11  cvss_userInteraction        167 non-null    category
     12  cvss_scope                  167 non-null    category
     13  cvss_confidentialityImpact  167 non-null    category
     14  cvss_integrityImpact        167 non-null    category
     15  cvss_availabilityImpact     167 non-null    category
    dtypes: category(12), float64(1), object(3)
    memory usage: 12.0+ KB


## Downloading NVD 2022-2025 database
We start by downloading all the CVEs that have been published between 2022 and 2024. This is because EPSS data is only available from 2021, and since we want to analyze CVEs behavior from when they were published, we need CVEs from after 2021.


```python
base_url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
ext = ".json.gz"
NVD_API_KEY = "c13c3940-8ebd-4073-ad37-d2507719f385" # insert your key

base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
cve_date_start = date(2022, 1, 1)
cve_date_end = date(2025, 6, 1)
cve_window_start = cve_date_start
cves = []

while cve_window_start + timedelta(days=30) <= cve_date_end:
    start_index = 0
    results_per_page = 1000
    total_results = 1
    date_start_NVD = f'{cve_window_start}T00:00:00.001Z'
    date_end_NVD = f'{cve_window_start + timedelta(days=30)}T00:00:00.000Z'
    print(f"Downloading CVEs between {date_start_NVD} and {date_end_NVD}...")
    while start_index < total_results:
        params = {
            "pubStartDate": date_start_NVD,
            "pubEndDate": date_end_NVD,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            "noRejected": "",
            #"apiKey": NVD_API_KEY
        }
        response = requests.get(base_url, params=params, timeout=6)
        if response.status_code != 200:
            print("Error:", response.status_code)
            break
        data = response.json()
        total_results = data.get("totalResults", 0)
        cves.extend(data.get("vulnerabilities", []))
        start_index += results_per_page
        print(start_index)
        sleep(1)
    sleep(5)
    cve_window_start += timedelta(days=30)
```

    Downloading CVEs between 2022-01-01T00:00:00.001Z and 2022-01-31T00:00:00.000Z...
    1000
    2000
    ...

```python
# normalize and preprocess data
cves_df = pd.json_normalize(cves, record_path=None, sep='.', max_level=None)
cves_df = preprocess_NVD_data(cves_df)
```


```python
# remove vulnerabilities marked as "reject" or "reserved"
cves_df = cves_df[(cves_df['cve.vulnStatus'] != 'Reserved') & (cves_df['cve.vulnStatus'] != 'Reject')]
```


```python
cves_df.describe()
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>cve.published</th>
      <th>cve.lastModified</th>
      <th>num_references</th>
      <th>cvss_baseScore</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>count</th>
      <td>111888</td>
      <td>111888</td>
      <td>111888.000000</td>
      <td>111053.000000</td>
    </tr>
    <tr>
      <th>mean</th>
      <td>2023-11-29 17:34:50.145608192</td>
      <td>2025-02-08 05:55:14.759742208</td>
      <td>3.717905</td>
      <td>7.004528</td>
    </tr>
    <tr>
      <th>min</th>
      <td>2022-01-01 00:15:08.057000</td>
      <td>2024-07-31 12:57:02.300000</td>
      <td>1.000000</td>
      <td>0.000000</td>
    </tr>
    <tr>
      <th>25%</th>
      <td>2023-02-08 19:15:11.409250048</td>
      <td>2024-11-21 07:19:55.312499968</td>
      <td>2.000000</td>
      <td>5.500000</td>
    </tr>
    <tr>
      <th>50%</th>
      <td>2024-01-24 02:45:07.666500096</td>
      <td>2024-11-21 09:32:53.486500096</td>
      <td>2.000000</td>
      <td>7.100000</td>
    </tr>
    <tr>
      <th>75%</th>
      <td>2024-10-11 13:15:16.226999808</td>
      <td>2025-04-15 18:02:13.699749888</td>
      <td>4.000000</td>
      <td>8.100000</td>
    </tr>
    <tr>
      <th>max</th>
      <td>2025-05-14 20:15:21.927000</td>
      <td>2025-12-24 14:15:46.227000</td>
      <td>287.000000</td>
      <td>10.000000</td>
    </tr>
    <tr>
      <th>std</th>
      <td>NaN</td>
      <td>NaN</td>
      <td>3.660688</td>
      <td>1.704474</td>
    </tr>
  </tbody>
</table>
</div>




```python
cves_df.isnull().sum()
```




    cve.id                             0
    cve.sourceIdentifier               0
    cve.published                      0
    cve.lastModified                   0
    cve.vulnStatus                     0
    cve.references                     0
    cve.cisaExploitAdd            111365
    cve.cisaActionDue             111365
    cve.cisaRequiredAction        111365
    cve.cisaVulnerabilityName     111365
    cve.evaluatorComment          111878
    description                        0
    vulnerable_cpes                    0
    num_references                     0
    cwe_list                           0
    cvss_version                     835
    cvss_vectorString                835
    cvss_baseScore                   835
    cvss_baseSeverity                837
    cvss_attackVector                835
    cvss_attackComplexity            835
    cvss_privilegesRequired          835
    cvss_userInteraction             835
    cvss_scope                       835
    cvss_confidentialityImpact       835
    cvss_integrityImpact             835
    cvss_availabilityImpact          835
    dtype: int64



Some features have a high number of missing values, so we drop the columns directly. Due to the sheer amount of samples, we also remove all the rows that have a missing value. Since we will aggregate data from all the CVEs' histories, we also drop date-related columns.


```python
X = cves_df.drop(columns=["cve.cisaExploitAdd", "cve.evaluatorComment", "cve.cisaActionDue", "cve.cisaRequiredAction",
                          "cve.cisaVulnerabilityName", "cve.published", "cve.lastModified"]).dropna()
X.info()
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 111051 entries, 0 to 111887
    Data columns (total 20 columns):
     #   Column                      Non-Null Count   Dtype   
    ---  ------                      --------------   -----   
     0   cve.id                      111051 non-null  object  
     1   cve.sourceIdentifier        111051 non-null  object  
     2   cve.vulnStatus              111051 non-null  object  
     3   cve.references              111051 non-null  object  
     4   description                 111051 non-null  object  
     5   vulnerable_cpes             111051 non-null  object  
     6   num_references              111051 non-null  int64   
     7   cwe_list                    111051 non-null  object  
     8   cvss_version                111051 non-null  object  
     9   cvss_vectorString           111051 non-null  object  
     10  cvss_baseScore              111051 non-null  float64 
     11  cvss_baseSeverity           111051 non-null  category
     12  cvss_attackVector           111051 non-null  object  
     13  cvss_attackComplexity       111051 non-null  object  
     14  cvss_privilegesRequired     111051 non-null  object  
     15  cvss_userInteraction        111051 non-null  object  
     16  cvss_scope                  111051 non-null  object  
     17  cvss_confidentialityImpact  111051 non-null  object  
     18  cvss_integrityImpact        111051 non-null  object  
     19  cvss_availabilityImpact     111051 non-null  object  
    dtypes: category(1), float64(1), int64(1), object(17)
    memory usage: 17.1+ MB



```python
X.head(3).T
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>0</th>
      <th>1</th>
      <th>2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>cve.id</th>
      <td>CVE-2021-45929</td>
      <td>CVE-2021-45944</td>
      <td>CVE-2021-45946</td>
    </tr>
    <tr>
      <th>cve.sourceIdentifier</th>
      <td>cve@mitre.org</td>
      <td>cve@mitre.org</td>
      <td>cve@mitre.org</td>
    </tr>
    <tr>
      <th>cve.vulnStatus</th>
      <td>Modified</td>
      <td>Modified</td>
      <td>Modified</td>
    </tr>
    <tr>
      <th>cve.references</th>
      <td>[{'url': 'https://bugs.chromium.org/p/oss-fuzz...</td>
      <td>[{'url': 'https://bugs.chromium.org/p/oss-fuzz...</td>
      <td>[{'url': 'https://bugs.chromium.org/p/oss-fuzz...</td>
    </tr>
    <tr>
      <th>description</th>
      <td>Wasm3 0.5.0 has an out-of-bounds write in Comp...</td>
      <td>Ghostscript GhostPDL 9.50 through 9.53.3 has a...</td>
      <td>Wasm3 0.5.0 has an out-of-bounds write in Comp...</td>
    </tr>
    <tr>
      <th>vulnerable_cpes</th>
      <td>[cpe:2.3:a:wasm3_project:wasm3:0.5.0:*:*:*:*:*...</td>
      <td>[cpe:2.3:a:artifex:ghostscript:*:*:*:*:*:*:*:*...</td>
      <td>[cpe:2.3:a:wasm3_project:wasm3:0.5.0:*:*:*:*:*...</td>
    </tr>
    <tr>
      <th>num_references</th>
      <td>4</td>
      <td>14</td>
      <td>4</td>
    </tr>
    <tr>
      <th>cwe_list</th>
      <td>[CWE-787]</td>
      <td>[CWE-416]</td>
      <td>[CWE-787]</td>
    </tr>
    <tr>
      <th>cvss_version</th>
      <td>3.1</td>
      <td>3.1</td>
      <td>3.1</td>
    </tr>
    <tr>
      <th>cvss_vectorString</th>
      <td>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</td>
    </tr>
    <tr>
      <th>cvss_baseScore</th>
      <td>5.5</td>
      <td>5.5</td>
      <td>5.5</td>
    </tr>
    <tr>
      <th>cvss_baseSeverity</th>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
    </tr>
    <tr>
      <th>cvss_attackVector</th>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
    </tr>
    <tr>
      <th>cvss_attackComplexity</th>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
    </tr>
    <tr>
      <th>cvss_privilegesRequired</th>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_userInteraction</th>
      <td>REQUIRED</td>
      <td>REQUIRED</td>
      <td>REQUIRED</td>
    </tr>
    <tr>
      <th>cvss_scope</th>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
    </tr>
    <tr>
      <th>cvss_confidentialityImpact</th>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_integrityImpact</th>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_availabilityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
  </tbody>
</table>
</div>



Since all CVEs share the same CVSS version, we can remove that column from our dataset.


```python
X = X.drop(columns="cvss_version")
```

Even though the number of references and cpes could be very useful, since they refer to the status of the CVE at the moment of download and do not contain time series data, we cannot use them to asses how the CVE evolved during its first months after publication. For this reason, we drop those columns too from our dataset.


```python
X = X.drop(columns=["cve.references", "num_references", "vulnerable_cpes"])

```

We now transform all remaining variables into categorial ones.


```python
cols_to_cat = ["cve.sourceIdentifier", "cve.vulnStatus", "cvss_vectorString", "cvss_baseSeverity", "cvss_attackVector",
               "cvss_attackComplexity", "cvss_privilegesRequired", "cvss_userInteraction", "cvss_scope",
               "cvss_confidentialityImpact", "cvss_integrityImpact",
               "cvss_availabilityImpact"]
X[cols_to_cat] = X[cols_to_cat].astype('category')
```


```python
X.to_csv(os.path.join(data_path, "cves_df.csv"))
```

## Downloading historical EPSS data

For each CVE, we download its complete EPSS history. We take all CVEs that started with a percentile value < 1% and we calculate the following metrics for their first 3 months after publication:
- $\frac{\sum_{t=1}^{T}pct_{i,t}-pct_{i,0}}{T}, T = 90$
- $\text{max}_t(pct_{i,t}-pct_{i,0}), t\in[1,...,90]$


```python
window = 90

start_date = date(2022, 1, 1)
end_date = date(2025, 6, 1) + timedelta(days=window)
epss_path = os.path.join(data_path, "epss_history")
os.makedirs(epss_path, exist_ok=True)
while start_date <= end_date:
    url = "https://epss.empiricalsecurity.com/epss_scores-{:%Y-%m-%d}.csv.gz".format(start_date)
    filename = os.path.join(epss_path, f"epss_scores-{start_date:%Y-%m-%d}.csv.gz")

    # Skip if already downloaded
    if os.path.exists(filename):
        print(f"Skipping {filename} (already exists)")
    else:
        print(f"Downloading {url}...")
        response = requests.get(url)
        if response.status_code == 200:
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"Saved to {filename}")
        else:
            print(f"No file for {start_date:%Y-%m-%d} (HTTP {response.status_code})")
        sleep(1)
    start_date += timedelta(days=1)

print("Download complete.")
```

    Downloading https://epss.empiricalsecurity.com/epss_scores-2022-01-01.csv.gz...
    Saved to data/epss_history/epss_scores-2022-01-01.csv.gz
    Downloading https://epss.empiricalsecurity.com/epss_scores-2022-01-02.csv.gz...
    Saved to data/epss_history/epss_scores-2022-01-02.csv.gz
    Downloading https://epss.empiricalsecurity.com/epss_scores-2022-01-03.csv.gz...
    Saved to data/epss_history/epss_scores-2022-01-03.csv.gz
    Downloading https://epss.empiricalsecurity.com/epss_scores-2022-01-04.csv.gz...
    ...
    Download complete.



```python
# Loop through all .gz files
for filename in os.listdir(epss_path):
    gz_path = os.path.join(epss_path, filename)
    csv_path = os.path.join(epss_path, filename[:-3])  # Remove .gz
    if filename.endswith(".csv.gz") and not os.path.exists(csv_path):
        print(f"Unzipping {gz_path} -> {csv_path}")
        with gzip.open(gz_path, "rb") as f_in:
            with open(csv_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

print("All files unzipped successfully.")
```

    Unzipping data/epss_history/epss_scores-2022-01-01.csv.gz -> data/epss_history/epss_scores-2022-01-01.csv
    Unzipping data/epss_history/epss_scores-2022-01-02.csv.gz -> data/epss_history/epss_scores-2022-01-02.csv
    Unzipping data/epss_history/epss_scores-2022-01-03.csv.gz -> data/epss_history/epss_scores-2022-01-03.csv
    ...
    All files unzipped successfully.


We create a dictionary containing as keys all the CVEs published between 2022 and 2024, and as values a list of their first 90 percentile values since first publication on EPSS.


```python
percentiles_history = {}
r = 0
p = 0
# Loop through all CSV files
for filename in sorted(os.listdir(epss_path)):
    if filename.endswith(".csv") and filename.startswith("epss_scores-"):
        file_path = os.path.join(epss_path, filename)
        # Read file and acquire CVEs
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            print(f"Reading {filename}...")
            for row in reader:
                if len(row) >= 3 and row[0].strip().startswith(("CVE-2022", "CVE-2023", "CVE-2024", "CVE-2025")):
                    r += 1
                    if row[0].strip() not in percentiles_history:
                        percentiles_history[row[0].strip()] = []
                        if float(row[2].strip()) < 0.01:
                            p += 1
                    percentiles_history[row[0].strip()].append(float(row[2].strip()))

# We cap the percentiles at the first 90 days
for cve in percentiles_history:
    percentiles_history[cve] = percentiles_history[cve][0:90]
```

    Reading epss_scores-2022-01-01.csv...
    Reading epss_scores-2022-01-02.csv...
    Reading epss_scores-2022-01-03.csv...
    ...

```python
print(f"N of entries: {r}\n N of 1%: {p}")
```

    N of entries: 63880638
     N of 1%: 715


## Feature Construction using EPSS data


```python
def get_first_percentile(cveid):
    if cveid in percentiles_history:
        return percentiles_history[cveid][0]
    return None
```


```python
X = X[X["cve.id"].apply(lambda c: c in percentiles_history)]
```

$$\text{mean\_daily\_gain} = \frac{\sum_{t=1}^{T}pct_{i,t}-pct_{i,0}}{T} = \frac{(\sum_{t=1}^{T}pct_{i,t})-(T-1)pct_{i,0}}{T},  T = 90$$


```python
def mean_daily_gain(values):
    return (sum(values[1:-1]) - (len(values)-1)*values[0]) / len(values)
```

$$\text{total\_gain}=\text{max}_t(pct_{i,t}-pct_{i,0}), t\in[1,...,90]$$


```python
def total_gain(values):
    res = 0
    for value in values[1:-1]:
        res = max(res, value - values[0])
    return res
```


```python
# merge NVD and derivative metrics
X['initial_percentile'] = X["cve.id"].apply(get_first_percentile)
X['mean_daily_gain'] = X["cve.id"].apply(lambda c: mean_daily_gain(percentiles_history[c]))
X['total_gain'] = X["cve.id"].apply(lambda c: total_gain(percentiles_history[c]))
# save the final dataframe
X.to_csv(os.path.join(data_path, "cves_df.csv"))
```

As we can see from the following plots, CVEs tend to start with an EPSS score sitting in the 10%. It is also evident how the mean daily gain and total gain over the first 90 days after publishing sit close to zero, meaning the vast majority of CVEs do not increase their threat level.


```python
plt.figure(figsize=(12, 5))
plt.ylabel("contribution%")
plt.hist(X["initial_percentile"], bins="auto", density=True)
plt.xlabel("EPSS percentile on 1st day")
plt.show()

plt.figure(figsize=(12, 5))
plt.ylabel("contribution%")
plt.hist(X["mean_daily_gain"], bins=50, density=True)
plt.xlabel("Mean daily gain in first 90 days")
plt.show()

plt.figure(figsize=(12, 5))
plt.ylabel("contribution%")
plt.hist(x=X["total_gain"], bins=50, density=True)
plt.xlabel("Max gain in the first 90 days")
plt.xticks(rotation=90)
plt.tight_layout()
plt.show()

```


    
![png](LAB_EPSS_files/LAB_EPSS_78_0.png)
    



    
![png](LAB_EPSS_files/LAB_EPSS_78_1.png)
    



    
![png](LAB_EPSS_files/LAB_EPSS_78_2.png)
    



```python
X[X["initial_percentile"] < 0.01].info()
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 303 entries, 30171 to 111884
    Data columns (total 19 columns):
     #   Column                      Non-Null Count  Dtype   
    ---  ------                      --------------  -----   
     0   cve.id                      303 non-null    object  
     1   cve.sourceIdentifier        303 non-null    category
     2   cve.vulnStatus              303 non-null    category
     3   description                 303 non-null    object  
     4   cwe_list                    303 non-null    object  
     5   cvss_vectorString           303 non-null    category
     6   cvss_baseScore              303 non-null    float64 
     7   cvss_baseSeverity           303 non-null    category
     8   cvss_attackVector           303 non-null    category
     9   cvss_attackComplexity       303 non-null    category
     10  cvss_privilegesRequired     303 non-null    category
     11  cvss_userInteraction        303 non-null    category
     12  cvss_scope                  303 non-null    category
     13  cvss_confidentialityImpact  303 non-null    category
     14  cvss_integrityImpact        303 non-null    category
     15  cvss_availabilityImpact     303 non-null    category
     16  initial_percentile          303 non-null    float64 
     17  mean_daily_gain             303 non-null    float64 
     18  total_gain                  303 non-null    float64 
    dtypes: category(12), float64(4), object(3)
    memory usage: 77.8+ KB


There are only a few CVEs from 2022 to the middle of 2025 that have started with an EPSS below the 1% percentile. We will try two different ML-based approaches to select our final candidates to submit.


```python
#candidate_cves_df = candidate_cves_df.drop(columns=["cve", "cve.published", "cve.lastModified", "cvss_version", "cve.references", "num_references", "vulnerable_cpes"])
candidate_cves_df.info()
candidate_cves_df.to_csv(os.path.join(data_path, "candidate_cves_df.csv"))
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 167 entries, 20 to 4304
    Data columns (total 16 columns):
     #   Column                      Non-Null Count  Dtype   
    ---  ------                      --------------  -----   
     0   cve.id                      167 non-null    object  
     1   cve.sourceIdentifier        167 non-null    category
     2   cve.vulnStatus              167 non-null    category
     3   description                 167 non-null    object  
     4   cwe_list                    167 non-null    object  
     5   cvss_vectorString           167 non-null    category
     6   cvss_baseScore              167 non-null    float64 
     7   cvss_baseSeverity           167 non-null    category
     8   cvss_attackVector           167 non-null    category
     9   cvss_attackComplexity       167 non-null    category
     10  cvss_privilegesRequired     167 non-null    category
     11  cvss_userInteraction        167 non-null    category
     12  cvss_scope                  167 non-null    category
     13  cvss_confidentialityImpact  167 non-null    category
     14  cvss_integrityImpact        167 non-null    category
     15  cvss_availabilityImpact     167 non-null    category
    dtypes: category(12), float64(1), object(3)
    memory usage: 12.0+ KB


# START FROM HERE IF YOU ALREADY DOWNLOADED EVERYTHING


```python
import gzip
from io import BytesIO
from time import sleep

import numpy as np
import pandas
import pandas as pd
import os
import requests
import json
import csv
import shutil
from datetime import date, timedelta
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import KBinsDiscretizer
from pandas import concat
from sklearn.model_selection import train_test_split
from sklearn.svm import OneClassSVM
from sklearn.feature_selection import chi2
import seaborn as sns
import matplotlib.pyplot as plt

sns.set_theme(style="whitegrid")
from preprocessing_utils import preprocess_NVD_data

data_path = 'data'
if not os.path.exists(data_path):
    os.makedirs(data_path)
```


```python
X = pd.read_csv(os.path.join(data_path, "cves_df.csv")).drop(columns="Unnamed: 0")
candidate_cves_df = pd.read_csv(os.path.join(data_path, "candidate_cves_df.csv")).drop(columns="Unnamed: 0")
```


```python
X.info()
```

    <class 'pandas.core.frame.DataFrame'>
    RangeIndex: 102792 entries, 0 to 102791
    Data columns (total 19 columns):
     #   Column                      Non-Null Count   Dtype  
    ---  ------                      --------------   -----  
     0   cve.id                      102792 non-null  object 
     1   cve.sourceIdentifier        102792 non-null  object 
     2   cve.vulnStatus              102792 non-null  object 
     3   description                 102792 non-null  object 
     4   cwe_list                    102792 non-null  object 
     5   cvss_vectorString           102792 non-null  object 
     6   cvss_baseScore              102792 non-null  float64
     7   cvss_baseSeverity           102792 non-null  object 
     8   cvss_attackVector           102792 non-null  object 
     9   cvss_attackComplexity       102792 non-null  object 
     10  cvss_privilegesRequired     102792 non-null  object 
     11  cvss_userInteraction        102792 non-null  object 
     12  cvss_scope                  102792 non-null  object 
     13  cvss_confidentialityImpact  102792 non-null  object 
     14  cvss_integrityImpact        102792 non-null  object 
     15  cvss_availabilityImpact     102792 non-null  object 
     16  initial_percentile          102792 non-null  float64
     17  mean_daily_gain             102792 non-null  float64
     18  total_gain                  102792 non-null  float64
    dtypes: float64(4), object(15)
    memory usage: 14.9+ MB


## 1. Novelty detection on the filtered dataset

We train a OneClasSVM on the dataset filtered by percentile < 0.01. This training set will be considered the "losers", and we hope to find some CVEs among our candidates that are detected as outliers (novel) by the SVM.


```python
import sklearn
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import OneHotEncoder
```


```python
X_train_svm = X[X["initial_percentile"] < 0.01]
X_train_svm = X_train_svm.drop(
    columns=["initial_percentile", "mean_daily_gain", "total_gain", "cve.id", "description", "cwe_list"])
X_train_svm.info()
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 303 entries, 24214 to 102788
    Data columns (total 13 columns):
     #   Column                      Non-Null Count  Dtype  
    ---  ------                      --------------  -----  
     0   cve.sourceIdentifier        303 non-null    object 
     1   cve.vulnStatus              303 non-null    object 
     2   cvss_vectorString           303 non-null    object 
     3   cvss_baseScore              303 non-null    float64
     4   cvss_baseSeverity           303 non-null    object 
     5   cvss_attackVector           303 non-null    object 
     6   cvss_attackComplexity       303 non-null    object 
     7   cvss_privilegesRequired     303 non-null    object 
     8   cvss_userInteraction        303 non-null    object 
     9   cvss_scope                  303 non-null    object 
     10  cvss_confidentialityImpact  303 non-null    object 
     11  cvss_integrityImpact        303 non-null    object 
     12  cvss_availabilityImpact     303 non-null    object 
    dtypes: float64(1), object(12)
    memory usage: 33.1+ KB



```python
X_test_svm = X[X["initial_percentile"] >= 0.01]
X_test_svm = X_test_svm.drop(
    columns=["initial_percentile", "mean_daily_gain", "total_gain", "cve.id", "description", "cwe_list"])
X_test_svm.info()
```

    <class 'pandas.core.frame.DataFrame'>
    Index: 102489 entries, 0 to 102791
    Data columns (total 13 columns):
     #   Column                      Non-Null Count   Dtype  
    ---  ------                      --------------   -----  
     0   cve.sourceIdentifier        102489 non-null  object 
     1   cve.vulnStatus              102489 non-null  object 
     2   cvss_vectorString           102489 non-null  object 
     3   cvss_baseScore              102489 non-null  float64
     4   cvss_baseSeverity           102489 non-null  object 
     5   cvss_attackVector           102489 non-null  object 
     6   cvss_attackComplexity       102489 non-null  object 
     7   cvss_privilegesRequired     102489 non-null  object 
     8   cvss_userInteraction        102489 non-null  object 
     9   cvss_scope                  102489 non-null  object 
     10  cvss_confidentialityImpact  102489 non-null  object 
     11  cvss_integrityImpact        102489 non-null  object 
     12  cvss_availabilityImpact     102489 non-null  object 
    dtypes: float64(1), object(12)
    memory usage: 10.9+ MB



```python
encoder = OneHotEncoder()
print("Encoding categorial features...")
X_svm_encode = pd.concat(
    [X.drop(columns=["initial_percentile", "mean_daily_gain", "total_gain", "cve.id", "description", "cwe_list"]),
     candidate_cves_df.drop(columns=["cve.id", "description", "cwe_list"])])
encoder.fit(X_svm_encode)
X_train_svm_encoded = encoder.transform(X_train_svm)
X_test_svm_encoded = encoder.transform(X_test_svm)
```

    Encoding categorial features...



```python
estimator = OneClassSVM()
print("Fitting model...")
estimator.fit(X_train_svm_encoded)
```

    Fitting model...

```python
print("Testing...")
y_svm_test = estimator.predict(X_test_svm_encoded)
print(f"Accuracy on testing data: {len(y_svm_test[y_svm_test == -1]) / len(X_test_svm)}%")
```

    Testing...
    Accuracy on testing data: 0.8370166554459503%



```python
candidate_cves_df_encoded = encoder.transform(candidate_cves_df.drop(columns=["cve.id", "description", "cwe_list"]))
print("Predicting...")
y_svm_predict = estimator.predict(candidate_cves_df_encoded)
print(f"Outliars in candidates: {100 * len(y_svm_predict[y_svm_predict == -1]) / len(y_svm_predict):.02f}%")
y_svm_predict = ["Outlier" if p == -1 else "Inlier" for p in y_svm_predict]
print(y_svm_predict)
```

    Predicting...
    Outliars in candidates: 31.14%
    ['Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Inlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Outlier', 'Inlier', 'Outlier', 'Outlier', 'Inlier', 'Inlier', 'Inlier', 'Inlier', 'Outlier', 'Outlier']


## 2 Metrics prediction on the filtered dataset

We try to train a RandomForestRegressor on the dataset filtered by percentile < 0.01.


```python
import sklearn
from sklearn.ensemble import RandomForestRegressor
from sklearn.multioutput import MultiOutputRegressor
from sklearn.preprocessing import OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_absolute_error, mean_squared_error, root_mean_squared_error, accuracy_score
```


```python
encoder = OneHotEncoder()
print("Encoding categorial features...")
X_rr_features = X[X["initial_percentile"] < 0.01]
X_rr_features = X.drop(
    columns=["initial_percentile", "mean_daily_gain", "total_gain", "cve.id", "description", "cwe_list"])
X_rr_encode = pd.concat([X_rr_features, candidate_cves_df.drop(columns=["cve.id", "description", "cwe_list"])])
encoder.fit(X_rr_encode)
X_rr_features_encoded = encoder.transform(X_rr_features)
print("Generating train/test split...")
targets = ["mean_daily_gain", "total_gain"]
y_rr_targets = X[targets]
X_rr_train, X_rr_test, y_rr_train, y_rr_test = train_test_split(X_rr_features_encoded,
                                                                y_rr_targets,
                                                                test_size=0.33,
                                                                random_state=42)
```

    Encoding categorial features...
    Generating train/test split...



```python
print("Fitting model...")
rr = RandomForestRegressor(n_estimators=1000, random_state=42, n_jobs=-1)
estimator = MultiOutputRegressor(rr)
estimator.fit(X_rr_train, y_rr_train)
```

    Fitting model...

```python
print("Testing...")
y_rr_predict = estimator.predict(X_rr_test)
print("R^2 per target:", r2_score(y_rr_test, y_rr_predict, multioutput='raw_values'))
print("MSE per target:", mean_squared_error(y_rr_test, y_rr_predict, multioutput='raw_values'))
print("RMSE per target:", root_mean_squared_error(y_rr_test, y_rr_predict, multioutput='raw_values'))
```

    Testing...
    R^2 per target: [0.27347186 0.21435853]
    MSE per target: [0.01228252 0.01534275]
    RMSE per target: [0.11082653 0.12386584]



```python
candidate_cves_df_encoded = encoder.transform(candidate_cves_df.drop(columns=["cve.id", "description", "cwe_list"]))
print("Predicting...")
y_rr_predict = estimator.predict(candidate_cves_df_encoded)
print(y_rr_predict)
```

    Predicting...
    [[-4.08929666e-02  7.46945614e-03]
     [-4.08929666e-02  7.46945614e-03]
     [ 8.22116723e-05  1.16986846e-02]
     ...
     [-1.80569075e-02  1.83473706e-02]
     [-3.23802192e-03  5.77080692e-02]]


# Final analysis

We now merge the predictions with the candidates. Due to some changes in the models, the predicted CVEs are different from the ones provided in the original LAB, so even though they might not appear I will choose in the end the ones submitted for the challenge.


```python
candidate_cves_df["Status"] = y_svm_predict
candidate_cves_df["predicted_mean_daily_gain"] = y_rr_predict.T[0]
candidate_cves_df["predicted_total_gain"] = y_rr_predict.T[1]
candidate_cves_df.T
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>0</th>
      <th>1</th>
      <th>2</th>
      <th>3</th>
      <th>4</th>
      <th>5</th>
      <th>6</th>
      <th>7</th>
      <th>8</th>
      <th>9</th>
      <th>...</th>
      <th>157</th>
      <th>158</th>
      <th>159</th>
      <th>160</th>
      <th>161</th>
      <th>162</th>
      <th>163</th>
      <th>164</th>
      <th>165</th>
      <th>166</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>cve.id</th>
      <td>CVE-2025-20705</td>
      <td>CVE-2025-20706</td>
      <td>CVE-2025-20707</td>
      <td>CVE-2024-49720</td>
      <td>CVE-2024-49722</td>
      <td>CVE-2024-49728</td>
      <td>CVE-2024-49730</td>
      <td>CVE-2025-22416</td>
      <td>CVE-2025-22417</td>
      <td>CVE-2025-22418</td>
      <td>...</td>
      <td>CVE-2025-9905</td>
      <td>CVE-2025-34200</td>
      <td>CVE-2025-43809</td>
      <td>CVE-2025-54855</td>
      <td>CVE-2025-39889</td>
      <td>CVE-2025-21481</td>
      <td>CVE-2025-7691</td>
      <td>CVE-2025-5069</td>
      <td>CVE-2025-57852</td>
      <td>CVE-2025-23291</td>
    </tr>
    <tr>
      <th>cve.sourceIdentifier</th>
      <td>security@mediatek.com</td>
      <td>security@mediatek.com</td>
      <td>security@mediatek.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>security@android.com</td>
      <td>...</td>
      <td>cve-coordination@google.com</td>
      <td>disclosure@vulncheck.com</td>
      <td>security@liferay.com</td>
      <td>ics-cert@hq.dhs.gov</td>
      <td>416baaa9-dc9f-4396-8d5f-8c081fb06d67</td>
      <td>product-security@qualcomm.com</td>
      <td>cve@gitlab.com</td>
      <td>cve@gitlab.com</td>
      <td>secalert@redhat.com</td>
      <td>psirt@nvidia.com</td>
    </tr>
    <tr>
      <th>cve.vulnStatus</th>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>...</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Awaiting Analysis</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Analyzed</td>
      <td>Awaiting Analysis</td>
      <td>Awaiting Analysis</td>
    </tr>
    <tr>
      <th>description</th>
      <td>In monitor_hang, there is a possible memory co...</td>
      <td>In mbrain, there is a possible memory corrupti...</td>
      <td>In geniezone, there is a possible memory corru...</td>
      <td>In multiple functions of Permissions.java, the...</td>
      <td>In showAvatarPicker of EditUserPhotoController...</td>
      <td>In generateFileInfo of BluetoothOppSendFileInf...</td>
      <td>In FuseDaemon.cpp, there is a possible out of ...</td>
      <td>In onCreate of ChooserActivity.java , there is...</td>
      <td>In finishTransition of Transition.java, there ...</td>
      <td>In multiple locations, there is a possible con...</td>
      <td>...</td>
      <td>The Keras Model.load_model method can be explo...</td>
      <td>Vasion Print (formerly PrinterLogic) Virtual A...</td>
      <td>Cross-Site Request Forgery (CSRF) vulnerabilit...</td>
      <td>Cleartext storage of sensitive information was...</td>
      <td>In the Linux kernel, the following vulnerabili...</td>
      <td>Memory corruption while performing private key...</td>
      <td>A privilege escalation issue has been discover...</td>
      <td>An issue has been discovered in GitLab CE/EE a...</td>
      <td>A container privilege escalation flaw was foun...</td>
      <td>NVIDIA Delegated Licensing Service for all app...</td>
    </tr>
    <tr>
      <th>cwe_list</th>
      <td>['CWE-416']</td>
      <td>['CWE-416']</td>
      <td>['CWE-416']</td>
      <td>['CWE-693']</td>
      <td>['CWE-610']</td>
      <td>['CWE-610']</td>
      <td>['CWE-787']</td>
      <td>['CWE-441']</td>
      <td>['CWE-1021']</td>
      <td>['CWE-441']</td>
      <td>...</td>
      <td>['CWE-913']</td>
      <td>['CWE-312']</td>
      <td>['CWE-352']</td>
      <td>['CWE-312']</td>
      <td>['CWE-326']</td>
      <td>['CWE-120']</td>
      <td>['CWE-267']</td>
      <td>['CWE-708']</td>
      <td>['CWE-276']</td>
      <td>['CWE-312']</td>
    </tr>
    <tr>
      <th>cvss_vectorString</th>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>...</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</td>
      <td>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</td>
      <td>CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:H/A:L</td>
      <td>CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N</td>
    </tr>
    <tr>
      <th>cvss_baseScore</th>
      <td>7.8</td>
      <td>7.8</td>
      <td>6.7</td>
      <td>7.8</td>
      <td>5.5</td>
      <td>5.5</td>
      <td>7.8</td>
      <td>7.8</td>
      <td>7.3</td>
      <td>7.8</td>
      <td>...</td>
      <td>7.3</td>
      <td>7.8</td>
      <td>4.3</td>
      <td>4.2</td>
      <td>5.5</td>
      <td>7.8</td>
      <td>8.8</td>
      <td>6.5</td>
      <td>5.2</td>
      <td>2.4</td>
    </tr>
    <tr>
      <th>cvss_baseSeverity</th>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>MEDIUM</td>
      <td>HIGH</td>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>...</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>MEDIUM</td>
      <td>MEDIUM</td>
      <td>LOW</td>
    </tr>
    <tr>
      <th>cvss_attackVector</th>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>...</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>NETWORK</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>LOCAL</td>
      <td>NETWORK</td>
      <td>NETWORK</td>
      <td>LOCAL</td>
      <td>ADJACENT_NETWORK</td>
    </tr>
    <tr>
      <th>cvss_attackComplexity</th>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>...</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
    <tr>
      <th>cvss_privilegesRequired</th>
      <td>LOW</td>
      <td>LOW</td>
      <td>HIGH</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>...</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>LOW</td>
      <td>HIGH</td>
      <td>HIGH</td>
    </tr>
    <tr>
      <th>cvss_userInteraction</th>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>REQUIRED</td>
      <td>NONE</td>
      <td>...</td>
      <td>REQUIRED</td>
      <td>NONE</td>
      <td>REQUIRED</td>
      <td>REQUIRED</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>REQUIRED</td>
    </tr>
    <tr>
      <th>cvss_scope</th>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>...</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>UNCHANGED</td>
      <td>CHANGED</td>
    </tr>
    <tr>
      <th>cvss_confidentialityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>...</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>LOW</td>
      <td>LOW</td>
    </tr>
    <tr>
      <th>cvss_integrityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>...</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>LOW</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>cvss_availabilityImpact</th>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>...</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>LOW</td>
      <td>NONE</td>
    </tr>
    <tr>
      <th>Status</th>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Outlier</td>
      <td>Inlier</td>
      <td>...</td>
      <td>Outlier</td>
      <td>Inlier</td>
      <td>Outlier</td>
      <td>Outlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Inlier</td>
      <td>Outlier</td>
      <td>Outlier</td>
    </tr>
    <tr>
      <th>predicted_mean_daily_gain</th>
      <td>-0.040893</td>
      <td>-0.040893</td>
      <td>0.000082</td>
      <td>0.00426</td>
      <td>0.000752</td>
      <td>0.000752</td>
      <td>0.00426</td>
      <td>0.00426</td>
      <td>0.003007</td>
      <td>0.00426</td>
      <td>...</td>
      <td>-0.036217</td>
      <td>0.005262</td>
      <td>0.047927</td>
      <td>-0.028177</td>
      <td>-0.00905</td>
      <td>-0.006007</td>
      <td>0.037021</td>
      <td>-0.024831</td>
      <td>-0.018057</td>
      <td>-0.003238</td>
    </tr>
    <tr>
      <th>predicted_total_gain</th>
      <td>0.007469</td>
      <td>0.007469</td>
      <td>0.011699</td>
      <td>0.027022</td>
      <td>0.011677</td>
      <td>0.011677</td>
      <td>0.027022</td>
      <td>0.027022</td>
      <td>0.010376</td>
      <td>0.027022</td>
      <td>...</td>
      <td>0.027669</td>
      <td>0.01115</td>
      <td>0.045327</td>
      <td>0.008806</td>
      <td>0.021808</td>
      <td>0.024627</td>
      <td>0.118635</td>
      <td>0.014713</td>
      <td>0.018347</td>
      <td>0.057708</td>
    </tr>
  </tbody>
</table>
<p>19 rows × 167 columns</p>
</div>



We only care about outliers, so we drop the others.


```python
candidate_cves_df = candidate_cves_df[candidate_cves_df["Status"] == "Outlier"].drop(columns="Status")
```

We now sort the remaining CVEs by their two target metrics:


```python
candidate_cves_df = candidate_cves_df.sort_values(by=["predicted_mean_daily_gain", "predicted_total_gain"], ascending=False)
```

At a cursory glance, we can see that all of Apple's and JetBrains' CVEs have already been fixed prior to publication, thus we exclude them.


```python
candidate_cves_df = candidate_cves_df[candidate_cves_df["cve.sourceIdentifier"] != "cve@jetbrains.com"]
candidate_cves_df = candidate_cves_df[candidate_cves_df["cve.sourceIdentifier"] != "product-security@apple.com"]
candidate_cves_df.head(10)
```




<div>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>cve.id</th>
      <th>cve.sourceIdentifier</th>
      <th>cve.vulnStatus</th>
      <th>description</th>
      <th>cwe_list</th>
      <th>cvss_vectorString</th>
      <th>cvss_baseScore</th>
      <th>cvss_baseSeverity</th>
      <th>cvss_attackVector</th>
      <th>cvss_attackComplexity</th>
      <th>cvss_privilegesRequired</th>
      <th>cvss_userInteraction</th>
      <th>cvss_scope</th>
      <th>cvss_confidentialityImpact</th>
      <th>cvss_integrityImpact</th>
      <th>cvss_availabilityImpact</th>
      <th>predicted_mean_daily_gain</th>
      <th>predicted_total_gain</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>147</th>
      <td>CVE-2025-9708</td>
      <td>jordan@liggitt.net</td>
      <td>Awaiting Analysis</td>
      <td>A vulnerability exists in the Kubernetes C# cl...</td>
      <td>['CWE-295']</td>
      <td>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N</td>
      <td>6.8</td>
      <td>MEDIUM</td>
      <td>NETWORK</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>REQUIRED</td>
      <td>UNCHANGED</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>NONE</td>
      <td>0.064613</td>
      <td>0.016485</td>
    </tr>
    <tr>
      <th>23</th>
      <td>CVE-2025-54588</td>
      <td>security-advisories@github.com</td>
      <td>Analyzed</td>
      <td>Envoy is an open source L7 proxy and communica...</td>
      <td>['CWE-416']</td>
      <td>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</td>
      <td>7.5</td>
      <td>HIGH</td>
      <td>NETWORK</td>
      <td>LOW</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>UNCHANGED</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>HIGH</td>
      <td>0.052709</td>
      <td>0.092191</td>
    </tr>
    ...
    <tr>
      <th>119</th>
      <td>CVE-2025-48581</td>
      <td>security@android.com</td>
      <td>Modified</td>
      <td>In VerifyNoOverlapInSessions of apexd.cpp, the...</td>
      <td>['CWE-754']</td>
      <td>CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td>
      <td>8.4</td>
      <td>HIGH</td>
      <td>LOCAL</td>
      <td>LOW</td>
      <td>NONE</td>
      <td>NONE</td>
      <td>UNCHANGED</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>HIGH</td>
      <td>-0.234255</td>
      <td>0.008857</td>
    </tr>
  </tbody>
</table>
</div>



By manual inspection, we also exclude CVE-2025-7445 and CVE-2025-59934 since they have been fixed. This leaves us with the first remaining 10 CVEs, which we will select for the lab activity.


```python
candidate_cves_df = candidate_cves_df[candidate_cves_df["cve.id"] != "CVE-2025-7445"]
candidate_cves_df = candidate_cves_df[candidate_cves_df["cve.id"] != "CVE-2025-59934"]
candidate_cves_df
```


```python
candidate_cves_df.to_csv(os.path.join(data_path, "candidate_cves_ranked_df.csv"))
```


```python
nickname = 'ora_et_LABora'

selected = ['CVE-2025-9364',
            'CVE-2025-50255',
            'CVE-2025-54588',
            'CVE-2025-57520',
            'CVE-2025-20364',
            'CVE-2025-10205',
            'CVE-2025-36899',
            'CVE-2025-26419',
            'CVE-2025-26420',
            'CVE-2025-26427',
            ]

candidate_cves_df = candidate_cves_df[candidate_cves_df["cve.id"].isin(selected)]
candidate_cves_df.to_csv(os.path.join(data_path, f'{nickname}.csv'))
```

## Tracking my CVEs


```python
import io
import sys
import datetime as dt
from typing import List, Optional
import pandas as pd
import requests
import seaborn as sns
import matplotlib.pyplot as plt
```


```python
selected = ['CVE-2025-9364',
            'CVE-2025-50255',
            'CVE-2025-54588',
            'CVE-2025-57520',
            'CVE-2025-20364',
            'CVE-2025-10205',
            'CVE-2025-36899',
            'CVE-2025-26419',
            'CVE-2025-26420',
            'CVE-2025-26427',
            ]

START = dt.date(2025, 10, 1)
END = dt.date.today()   # adjust if you want a fixed end date

BASE = "https://epss.empiricalsecurity.com/epss_scores-{:%Y-%m-%d}.csv.gz"  # daily CSV
TIMEOUT = 30

def fetch_day(d: dt.date, targets: List[str]) -> Optional[pd.DataFrame]:
    url = BASE.format(d)
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code != 200:
            return None  # file not published (weekend/lag) or no data yet
        df = pd.read_csv(io.BytesIO(r.content), compression='gzip', comment='#',
                         usecols=['cve', 'epss', 'percentile'])
        df = df[df['cve'].isin(targets)].copy()
        if df.empty:
            return None
        df['date'] = pd.to_datetime(d)
        # numeric dtypes
        df['epss'] = pd.to_numeric(df['epss'], errors='coerce')
        df['percentile'] = pd.to_numeric(df['percentile'], errors='coerce')
        return df[['date', 'cve', 'epss', 'percentile']]
    except requests.RequestException:
        return None

dates = pd.date_range(START, END, freq='D').date
frames = []
miss = 0
for i, d in enumerate(dates, 1):
    out = fetch_day(d, selected)
    if out is not None:
        frames.append(out)
    else:
        miss += 1
    if i % 10 == 0 or i == len(dates):
        print(f"[{i}/{len(dates)}] collected={len(frames)}, missing_or_empty={miss}", file=sys.stderr)

hist = pd.concat(frames, ignore_index=True).sort_values(['cve', 'date'])

all_days = pd.DataFrame({'date': pd.to_datetime(list(dates))})
hist = (hist
        .merge(all_days, on='date', how='right')  # keep all calendar days
        .sort_values(['cve', 'date']))

```

```python
plt.figure(figsize=(12, 6))
ax = sns.lineplot(data=hist, x='date', y='epss', hue='cve', marker=None, linewidth=1.6)
ax.set_title('EPSS history (probability) — Oct 1, 2025 to today', fontsize=13)
ax.set_xlabel('Data date (UTC daily publication)')
ax.set_ylabel('EPSS probability (0–1)')
ax.legend(title='CVE', ncol=2, fontsize=8)
plt.tight_layout()
plt.show()

```


    
![png](LAB_EPSS_files/LAB_EPSS_116_0.png)

## Disclosure
Some LLMs have been used to write parts of the code in this document.
    

