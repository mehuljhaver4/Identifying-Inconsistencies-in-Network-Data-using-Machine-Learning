##  the purpose of this program is to apply machine learning algorithms to the dataset and observe the performance of algorithms.
##  the algorithms used are:Naive Bayes, Random Forest, ID3, AdaBoost, Nearest Neighbors
## creates data visulaization for both files attack_files and all_data file.
from sklearn import metrics
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.metrics import average_precision_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score
from sklearn.metrics import recall_score
from sklearn.metrics import precision_score
            
import matplotlib.pyplot as plt
from sklearn import preprocessing
import numpy as np
#%matplotlib inline
import os
import pandas as pd
import csv
import time
import warnings
import math


warnings.filterwarnings("ignore")
def create_folder(name): 
    try:
        if not os.path.exists(name):
            os.makedirs(name)
    except OSError:
        print ("Error while creating the folder")
        

output="./results/results_Final.csv" 
csv_files=["all_data.csv"]# CSV files names: #The names of the dataset files (csv_files).
path=""
recurrence=10


def create_folder(name): 
    try:
        if not os.path.exists(name):
            os.makedirs(name)
    except OSError:
        print ("The create_folder could not be created!")

folder_name="./results/"
create_folder(folder_name)
folder_name="./results/result_graph_Final/"
create_folder(folder_name)


# this list is used for features for final implementation of attack_files.csv
# this feature list contains 20 common feature hits when comparing all attacks
feature_list_all=["Bwd Packet Length Std","Flow Bytes/s","Total Length of Fwd Packets","Fwd Packet Length Std","Flow IAT Std",
"Flow IAT Min","Fwd IAT Total","Flow Duration","Bwd Packet Length Max","Flow IAT Max","Flow IAT Mean","Total Length of Bwd Packets",
"Fwd Packet Length Min","Bwd Packet Length Mean","Flow Packets/s","Fwd Packet Length Mean","Total Backward Packets","Total Fwd Packets",
"Fwd Packet Length Max","Bwd Packet Length Min",'Label']

#list of all ML algo implemented.
list_ml={
"Naive Bayes":GaussianNB(),
"Random Forest":RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
"ID3" :DecisionTreeClassifier(max_depth=5,criterion="entropy"),
"AdaBoost":AdaBoostClassifier(),
"Nearest Neighbors":KNeighborsClassifier(3)}

#this list contains features extracted from all_data.csv files.
all_data_features=["Bwd Packet Length Std", "Flow Bytes/s", "Total Length of Fwd Packets", "Fwd Packet Length Std",
     "Flow IAT Std", "Flow IAT Min", "Fwd IAT Total"]

attack_features={"Naive Bayes":['Bwd Packet Length Std', 'Total Length of Fwd Packets', 'Flow IAT Min', 'Fwd Packet Length Min', 'Flow Packets/s', 'Fwd Packet Length Mean'] ,
"Random Forest":all_data_features,
"ID3" :all_data_features,
"AdaBoost":all_data_features,
"Nearest Neighbors":all_data_features}

seconds=time.time()#time stamp for all processing time


with open(output, "w", newline="",encoding="utf-8") as f:#a CSV file is created to save the results obtained.
    write = csv.writer(f)
    write.writerow(["File","ML algorithm","accuracy","Precision", "Recall" , "F1-score","Time"])

for j in csv_files:
    print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % ("File","ML algorithm","accuracy","Precision", "Recall" , "F1-score","Time"))# print output header
    feature_list=feature_list_all
    df=pd.read_csv(path+j,feature_list_all=feature_list)#read an attack file.
    df=df.fillna(0)
    benign_or_malicious=[]
    for i in df["Label"]: 
        if i =="BENIGN":
            benign_or_malicious.append(1)
        else:
            benign_or_malicious.append(0)           
    df["Label"]=benign_or_malicious

    
    y = df["Label"] 
    del df["Label"]
    feature_list.remove('Label')    
    for ii in list_ml: 
        X = df[attack_features[ii]]
        preci=[]
        recall=[]
        f1=[]
        accuracy=[]
        total_time=[]
        for i in range(recurrence): 
            second=time.time()
            X_train, X_test, y_train, y_test = train_test_split(X, y,
                test_size = 0.20, random_state = recurrence)
            classifier = list_ml[ii]                                                                         
            classifier.fit(X_train, y_train)
            predict =classifier.predict(X_test)  
            f_1=f1_score(y_test, predict, average='macro')
            pr=precision_score(y_test, predict, average='macro')
            rc=recall_score(y_test, predict, average='macro')      
            preci.append(float(pr))
            recall.append(float(rc))
            f1.append(float(f_1))
            accuracy.append(classifier.score(X_test, y_test))
            total_time.append(float((time.time()-second)) )


            
        print ('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % (j[0:-4],ii,str(round(np.mean(accuracy),2)),str(round(np.mean(preci),2)), 
            str(round(np.mean(recall),2)),str(round(np.mean(f1),2)),str(round(np.mean(total_time),4))))#the avarage output of the ten repetitions is printed on the screen.

        with open(output, "a", newline="",encoding="utf-8") as f: # all the values found are saved in the opened file.
            write = csv.writer(f)
            for i in range(0,len(total_time)):
                write.writerow([j[0:-4],ii,accuracy[i],preci[i],recall[i],f1[i],total_time[i]])#file name, algorithm name, preci, recall and f-measure are writed in CSV file



        # In this section, Box graphics are created for the results of machine learning algorithms and saved in the feaure_graph create_folder.
        plt.boxplot(f1)
        plt.title("All Dataset - " +str(ii))
        plt.ylabel('F-measure')
        plt.savefig(folder_name+j[0:-4]+str(ii)+".pdf",bbox_inches='tight', papertype = 'a4', orientation = 'portrait', format = 'pdf')
        plt.show()# you can remove the # sign if you want to see the graphics simultaneously
        
print("Final Statistical Analysis Completed")
print("Overall Time Taken: = ",time.time()- seconds ,"seconds")


