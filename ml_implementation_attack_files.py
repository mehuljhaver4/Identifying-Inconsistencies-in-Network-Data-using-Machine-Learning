##  This File as the name suggest implements various ML algorithms on the attack csv files.
##  ML Algo implemented are as follows : NaiveBayes, ID3, AdaBoost, KNN and Random Forest 
##  Performance Metrics have also been calculated such as accuracy,Precision, Recall, F1-score,Time
##  this code outputs data visualization and csv files.

from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import metrics
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score

import os
import pandas as pd
import csv
import time
import warnings
import math
import matplotlib.pyplot as plt
import numpy as np


warnings.filterwarnings("ignore")
output="./results/results_1.csv" 
#a CSV file "results_1" is created in which the outputs is saved.
csv=os.listdir("attacks")
path=".\\attacks\\"
recurrence=10

def create_folder(name): 
    try:
        if not os.path.exists(name):
            os.makedirs(name)
    except OSError:
        print ("Error while creating the folder")

folder_name="./results/"
create_folder(folder_name)
folder_name="./results/result_graph_1/"
create_folder(folder_name)


#Below dictionary saves the list of ML algorithms implemented.
ml_list={
"Naive Bayes":GaussianNB(),
"Random Forest":RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
"ID3" :DecisionTreeClassifier(max_depth=5,criterion="entropy"),
"AdaBoost":AdaBoostClassifier(),
"Nearest Neighbors":KNeighborsClassifier(3)}


# Here we have Hardcoded the features obtained using previous feature selection programs. 
# Each attack has been given their own feature in a dictionary-list format
features={"Bot":["Bwd Packet Length Mean","Flow IAT Max","Flow Duration","Flow IAT Min","Label"],
"DDoS":["Bwd Packet Length Std","Total Backward Packets","Fwd IAT Total","Flow Duration","Label"],
"DoS GoldenEye":["Flow IAT Max","Bwd Packet Length Std","Flow IAT Min","Total Backward Packets","Label"],
"DoS Hulk":["Bwd Packet Length Std","Fwd Packet Length Std","Fwd Packet Length Max","Flow IAT Min","Label"],
"DoS Slowhttptest":["Flow IAT Mean","Fwd Packet Length Min","Bwd Packet Length Mean","Total Length of Bwd Packets","Label"],
"DoS slowloris":["Flow IAT Mean","Total Length of Bwd Packets","Bwd Packet Length Mean","Total Fwd Packets","Label"],
"FTP-Patator":["Fwd Packet Length Max","Fwd Packet Length Std","Fwd Packet Length Mean","Bwd Packet Length Std","Label"],
"Heartbleed":["Total Backward Packets","Fwd Packet Length Max","Flow IAT Min","Bwd Packet Length Max","Label"],
"Infiltration":["Fwd Packet Length Max","Fwd Packet Length Mean","Flow Duration","Total Length of Fwd Packets","Label"],
"PortScan":["Flow Bytes/s","Total Length of Fwd Packets","Fwd IAT Total","Flow Duration","Label"],
"SSH-Patator":["Fwd Packet Length Max","Flow Duration","Flow IAT Max","Total Length of Fwd Packets","Label"],
"Web Attack":["Bwd Packet Length Std","Total Length of Fwd Packets","Flow Bytes/s","Flow IAT Max","Label"]}

sec=time.time()#time stamp for all processing time

with open(output, "w", newline="",encoding="utf-8") as f:
    write = csv.writer(f)
    write.writerow(["File","ML algorithm","accuracy","Precision", "Recall" , "F1-score","Time"])

for j in csv: #loop re-runs based on attacks, builds csv file for performance metrics
    print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % ("File","ML algorithm","accuracy", "Recall", "Precision","F1-score","Time"))
    x=[]
    
    feature_list=list(features[j[0:-4]])
    data_frame=pd.read_csv(path+j,usecols=feature_list)#read an attack file.
    data_frame=data_frame.fillna(0)
    benign_or_malicious=[]
    for i in data_frame["Label"]: #This loop is used to label benign as "1" and malicious attack as "0"
        
        if i =="BENIGN":
            benign_or_malicious.append(1)
        else:
            benign_or_malicious.append(0)           
    data_frame["Label"]=benign_or_malicious

    
    y = data_frame["Label"] 
    del data_frame["Label"]
    feature_list.remove('Label')
    X = data_frame[feature_list]

    
    for ii in ml_list: 
        preci=[]
        recall=[]
        f1=[]
        accuracy=[]
        total_time=[]
        for i in range(recurrence): # This loop allows cross-validation and machine learning algorithm to be repeated 10 times
            second=time.time()#time stamp for processing time

            # cross-validation
            X_train, X_test, y_train, y_test = train_test_split(X, y,#  data (X) and labels (y) are divided into 2 parts to be sent to the machine learning algorithm (80% train,%20 test). 
                test_size = 0.20, random_state = recurrence)#  So, in total there are 4 tracks: training data(X_train), training tag (y_train), test data(X_test) and test tag(y_test).


            #machine learning algorithm is applied in this section
            clf = ml_list[ii]#choose algorithm from ml_list dictionary                                                                          
            clf.fit(X_train, y_train)
            predict =clf.predict(X_test)
        
            #makes "classification report" and assigns the preci, f-measure, and recall values.s.    
            f_1=f1_score(y_test, predict, average='macro')
            pr=precision_score(y_test, predict, average='macro')
            rc=recall_score(y_test, predict, average='macro')

            
            preci.append(float(pr))
            recall.append(float(rc))
            f1.append(float(f_1))
            accuracy.append(clf.score(X_test, y_test))
            total_time.append(float((time.time()-second)) )
            
        print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % (j[0:-4],ii,str(round(np.mean(accuracy),2)), str(round(np.mean(recall),2))
        ,str(round(np.mean(preci),2)),str(round(np.mean(f1),2)),str(round(np.mean(total_time),4))))

        with open(output, "x", newline="",encoding="utf-8") as f: 
            write = csv.writer(f)
            for i in range(0,len(total_time)):
                write.writerow([j[0:-4],ii,accuracy[i],recall[i], preci[i],f1[i],total_time[i]])
        x.append(f1)

   # This function makes a box plot with respect to the performance metrics for the given list of ML algorithms 

    ml=["Naive Bayes","Random Forest","ID3","AdaBoost","K Nearest Neighbors"]
    t=0
    fig, axes = plt.subplots(nrows=2, ncols=4, figsize=(12, 6), sharey=True)
    for c in range(2):
        for b in range(4):
            axes[c, b].boxplot(x[t] )
            axes[c, b].set_title(str(j[0:-4])+" - "+str(ml[t]),fontsize=7)
            axes[c, b].set_ylabel(("F measure"))
            t+=1
            if t==7:
                break
        if t==7:
            break
    plt.savefig(folder_name+j[0:-4]+".pdf",bbox_inches='tight', papertype = 'a4', orientation = 'portrait', format = 'pdf')
    plt.show()
    
print("We are done with Performance Analysis ()")
print("Overall Time taken = ",time.time()- sec ,"seconds")
