import random
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

elemination_type = 'original'  # oneToOne - oneToTwo - original

data_name_list = [
    'all',
    'Android-Universal-Image-Loader',
    'antlr4',
    'BroadleafCommerce',
    'ceylon-ide-eclipse',
    'elasticsearch',
    'hazelcast',
    'junit',
    'MapDB',
    'mcMMO',
    'mct',
    'neo4j',
    'netty',
    'orientdb',
    'oryx',
    'titan'
]

data_metrics_arr = []


def mapNumberOfBugs(row):
    return 1 if row['Number of Bugs'] > 0 else 0


def detect_outliers(df, features):
    outlier_indices = []

    for c in features:
        # 1st quartile
        Q1 = np.percentile(df[c], 25)
        # 3rd quartile
        Q3 = np.percentile(df[c], 75)
        # IQR
        IQR = Q3 - Q1
        # Outlier step
        outlier_step = IQR * 1.5
        # detect outlier and their indeces
        outlier_list_col = df[(df[c] < Q1 - outlier_step)
                              | (df[c] > Q3 + outlier_step)].index
        # store indeces
        outlier_indices.extend(outlier_list_col)

    outlier_indices = Counter(outlier_indices)
    multiple_outliers = list(i for i, v in outlier_indices.items() if v > 2)

    return multiple_outliers


def delete_rows(data, count):
    data_filtered = data[data['Number of Bugs'] == 0]
    data_filtered = random.sample(list(data_filtered.index), count)

    data = data.drop(data_filtered, axis=0).reset_index(drop=True)
    return data


for data_name in data_name_list:

    csv_file_name = elemination_type + '_elimination_metrics_'

    data = pd.read_csv(
        "BugHunterDataset/subtract/"+data_name+"/method.csv")

    data['Number of Bugs'] = data.apply(mapNumberOfBugs, axis=1)

    columns = []

    if str(data_name) == 'all':
        columns = ['Project']

    dropColumns = ['Hash', 'LongName', 'Vulnerability Rules', 'Finalizer Rules', 'Migration15 Rules', 'Migration14 Rules',
                   'Migration13 Rules', 'MigratingToJUnit4 Rules',
                   'JavaBean Rules', 'Coupling Rules', 'WarningBlocker', 'Code Size Rules', 'WarningInfo',
                   'Android Rules', 'Clone Implementation Rules', 'Comment Rules',
                   'WarningCritical', 'WarningMajor', 'WarningMinor', 'Basic Rules', 'Brace Rules',
                   'MI', 'MIMS', 'MISEI', 'MISM', 'NII', 'NUMPAR', 'Strict Exception Rules', 'String and StringBuffer Rules',
                   'Type Resolution Rules', 'Security Code Guideline Rules', 'Optimization Rules', 'Naming Rules',
                   "Java Logging Rules", "Jakarta Commons Logging Rules", "JUnit Rules", "J2EE Rules", "CLC", "CC", "CLLC",
                   "McCC", "NL", "NLE", "NOI", "CD", "Controversial Rules", "Empty Code Rules", "Migration Rules",
                   "HDIF", "HEFF", "HNDB", "HTRP", "CLOC", "DLOC", "TCD", "TCLOC", "CCO", "Import Statement Rules", "Unnecessary and Unused Code Rules",
                   "CCL", "CI", "LDC", "LLDC", "Design Rules"]

    columns = np.concatenate((columns, dropColumns), axis=0)

    data = data.drop(columns=columns)
    data_count = len(data)

    data = data.drop(detect_outliers(data, [
        "HCPL", "HPL", "HPV", "HVOL", "LLOC", "LOC", "NOS", "TLOC", "TNOS"]), axis=0).reset_index(drop=True)

    data_detect_outliers_count = len(data)
    data_filtered_nob_0 = data[data['Number of Bugs'] == 0]
    data_filtered_nob_1 = data[data['Number of Bugs'] == 1]

    count_of_rows_delete = 0

    if(elemination_type == 'oneToOne'):
        count_of_rows_delete = len(
            data_filtered_nob_0) - len(data_filtered_nob_1)
    else:
        count_of_rows_delete = len(
            data_filtered_nob_0) - len(data_filtered_nob_1) * 2

        if(count_of_rows_delete < -1):
            count_of_rows_delete = 0

    if(elemination_type != 'original'):
        data = delete_rows(data, count_of_rows_delete)

    data_filtered_nob_0 = data[data['Number of Bugs'] == 0]

    print("Data Name: ", data_name)
    print("Data Count: ", data_count)
    print("Data Detect Outliers Count: ", data_detect_outliers_count)
    print("Data Number of Bugs 0 Count: ", len(data_filtered_nob_0))
    print("Data Number of Bugs 1 Count: ", len(data_filtered_nob_1))
    print("Remaining Data Count: ", len(data))

    # Show Heat Map
    #f, ax = plt.subplots(figsize=(18,18))
    #sns.heatmap(data.corr(), annot=True, linewidths=.5, fmt ='.1f',ax=ax)

    metrics_obj = {
        "Data Name": data_name,
        "Data Count": data_count,
        "Data Detect Outliers Count": data_detect_outliers_count,
        "Data Number of Bugs 0 Count": len(data_filtered_nob_0),
        "Data Number of Bugs 1 Count": len(data_filtered_nob_1),
        "Remaining Data Count": len(data)
    }

    data_metrics_arr.append(metrics_obj)

    file_name = csv_file_name + data_name + '.csv'
    data.to_csv(file_name, index=False)

new_dataframe = pd.DataFrame(data_metrics_arr)
new_dataframe.to_excel("output_"+elemination_type+".xlsx")
