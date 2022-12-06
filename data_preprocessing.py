import pandas as pd
import os
from sklearn import preprocessing
import time
seconds = time.time()
get_ipython().run_line_magic('matplotlib', 'inline')

nmbr="0123456789"


data_labels=["Flow ID","Source IP","Source Port","Destination IP","Destination Port","Protocol","Timestamp","Flow Duration","Total Fwd Packets",
   "Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max","Fwd Packet Length Min",
   "Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
   "Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max",
   "Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
   "Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std",
   "Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWE Flag Count",
   "ECE Flag Count","Down/Up Ratio","Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size","faulty-Fwd Header Length","Fwd Avg Bytes/Bulk",
   "Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes",
   "Subflow Bwd Packets","Subflow Bwd Bytes","Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd",
   "min_seg_size_forward","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min","Label","External IP"]

data_files=["Monday-WorkingHours.pcap_ISCX",
        "Tuesday-WorkingHours.pcap_ISCX",
        "Wednesday-workingHours.pcap_ISCX",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX",
        "Friday-WorkingHours-Morning.pcap_ISCX",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX",]

data_labels2=data_labels
data_labels=( ",".join( i for i in data_labels ) )
data_labels=data_labels+"\n"
flag=True
for i in range(len(data_files)):
    fp_ths = open(str(i)+".csv", "w")
    fp_ths.write(data_labels)
    with open("./CSVs/"+data_files[i]+".csv", "r") as file:
        while True:
            try:
                line=file.readline()
                if  line[0] in nmbr:
                    if " – " in str(line):
                        line=(str(line).replace(" – "," - "))
                    line=(str(line).replace("inf","0"))
                    line=(str(line).replace("Infinity","0"))
                    
                    line=(str(line).replace("NaN","0"))
                     
                    fp_ths.write(str(line))
                else:
                    continue                       
            except:
                break
    fp_ths.close()
 
 
    df=pd.read_csv(str(i)+".csv",low_memory=False)
    df=df.fillna(0)

    str_feat=["Flow Bytes/s","Flow Packets/s"]
    for ft in str_feat:
        df[ft]=df[ft].replace('Infinity', -1)
        df[ft]=df[ft].replace('NaN', 0)
        num_not=[]
        for df_ft in df[ft]:
            try:
                k=int(float(df_ft))
                num_not.append(int(k))
            except:
                num_not.append(df_ft)
        df[ft]=num_not



    str_feat=[]
    for j in data_labels2:
        if df[j].dtype=="object":
            str_feat.append(j)
    try:
        str_feat.remove('Label')
    except:
        print("Error in removing!")
    labelencoder_X = preprocessing.LabelEncoder()



    for ft in str_feat:
        try:
            df[ft]=labelencoder_X.fit_transform(df[ft])
        except:
            df[ft]=df[ft].replace('Infinity', -1)
    df=df.drop(data_labels2[61], axis=1)


    if flag:
        df.to_csv('all_data.csv' ,index = False)
        flag=False
    else:
        df.to_csv('all_data.csv' ,index = False,header=False,mode="a")
    os.remove(str(i)+".csv")
    print("Pre-processing of the ",data_files[i]," file is completed.\n")

print("Total time taken = ",time.time()- seconds ,"secs")
    