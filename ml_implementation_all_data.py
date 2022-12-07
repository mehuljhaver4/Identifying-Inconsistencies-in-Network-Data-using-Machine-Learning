##  ML Algo implemented are as follows : NaiveBayes, ID3, AdaBoost, KNN and Random Forest 
##  Performance Metrics have also been calculated such as accuracy,Precision, Recall, F1-score,Time
##  this section of code outputs data visualization and csv files.

from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix
import os
import pandas as pd
import csv
import time
import warnings
import math
import matplotlib.pyplot as plt
import numpy as np

warnings.filterwarnings("ignore")
output="./results/results_2.csv" 
csv_files=["all_data.csv"]
recurrence=10

#creates folder for data visualizations and csv files
def create_folder(name):
    try:
        if not os.path.exists(name):
            os.makedirs(name)
    except OSError:
        print ("Error while creating the folder")

folder_name="./results/"
create_folder(folder_name)
folder_name="./results/result_graph_2/"
create_folder(folder_name)


#A dictionary list for each ML algorithms.
dict_list_ml={
"Naive Bayes":GaussianNB(),
"Random Forest":RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
"ID3" :DecisionTreeClassifier(max_depth=5,criterion="entropy"),
"AdaBoost":AdaBoostClassifier(),
"Nearest Neighbors":KNeighborsClassifier(3)}
# 7 features have been selected, these features are obtained from prior program which ran RandomForest Regressor on all_data.csv file.
features_list={"all_data":["Bwd Packet Length Std", "Flow Bytes/s", "Total Length of Fwd Packets", "Fwd Packet Length Std",
     "Flow IAT Std", "Flow IAT Min", "Fwd IAT Total","Label"]}

sec=time.time()

with open(output, "w", newline="",encoding="utf-8") as f:
    write = csv.writer(f)
    write.writerow(["File","ML algorithm","accuracy","Precision", "Recall" , "F1-score","Time"])


for k in csv_files:
    print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % ("File","ML algorithm","accuracy","Recall","Precision","F1-score","Time"))# print output header   
    feature_list=list(features_list[k[0:-4]])
    data_frame=pd.read_csv(path+k,usecols=feature_list)#read an attack file.
    data_frame=data_frame.fillna(0)
    benign_or_malicious=[]
    # This loop is used to label bening as 1 and malicious attack as 0
    for i in data_frame["Label"]: 
        if i =="BENIGN":
            benign_or_malicious.append(1)
        else:
            benign_or_malicious.append(0)           
    data_frame["Label"]=benign_or_malicious

    
    y = data_frame["Label"] 
    del data_frame["Label"]
    feature_list.remove('Label')
    X = data_frame[feature_list]

    # All the five algorithms are executed, this is done with the help of above created ML list.
    for ii in dict_list_ml: 
        preci=[]
        recall=[]
        f1=[]
        accuracy=[]
        total_time=[]
        for i in range(recurrence): 
            second=time.time()

            X_train, X_test, y_train, y_test = train_test_split(X, y,
                test_size = 0.20, random_state = recurrence)

            #ML algorithm are executed
            classifier = dict_list_ml[ii]                                                                         
            classifier.fit(X_train, y_train)
            predict =classifier.predict(X_test)
        
            #makes "classification report" and assigns the precision, f-measure, and recall values.   
            f_1=f1_score(y_test, predict, average='macro')
            pr=precision_score(y_test, predict, average='macro')
            rc=recall_score(y_test, predict, average='macro')
            preci.append(float(pr))
            recall.append(float(rc))
            f1.append(float(f_1))
            accuracy.append(classifier.score(X_test, y_test))
            total_time.append(float((time.time()-second)) )
            
        print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % (k[0:-4],ii,str(round(np.mean(accuracy),2)),str(round(np.mean(recall),2)),
        str(round(np.mean(preci),2)),str(round(np.mean(f1),2)),str(round(np.mean(total_time),4))))
        with open(output, "a", newline="",encoding="utf-8") as f: 
            write = csv.writer(f)
            for i in range(0,len(total_time)):
                write.writerow([k[0:-4],ii,accuracy[i],recall[i],preci[i],f1[i],total_time[i]])
        #data visulaization with repect to performance metrics are done via box plot
        plt.boxplot(f1)
        plt.title("All Dataset - " +str(ii))
        plt.ylabel('F-measure')
        plt.savefig(folder_name+k[0:-4]+str(ii)+".pdf",bbox_inches='tight', papertype = 'a4', orientation = 'portrait', format = 'pdf')
        plt.show()

print("Done with performance analysis for all_data")
print("Overall Time Taken: = ",time.time()- sec ,"seconds")
