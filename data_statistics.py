import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt 
import pandas as pd

def graph(objects,performance,x_label,y_label):
    y_pos = np.arange(len(objects))
    plt.barh(y_pos, performance, align='center', alpha=0.5)
    plt.yticks(y_pos, objects)
    plt.xlabel(x_label)
    plt.title(y_label)
    plt.show()


df=pd.read_csv('all_data.csv', usecols=["Label"])
print(df.iloc[:,0].value_counts())
a=(df.iloc[:,0].value_counts())

key=a.keys()
values=a.values
sm_lbls=[]
sm_vals=[]
bg_lbls=[]
bg_vals=[]
md_lbls=[]
md_vals=[]
attack=0
benign=0

for i in range(0,len(values)):
    if values[i]>11000:
        bg_lbls.append(str(key[i]))
        bg_vals.append(values[i])
    elif values[i]<600:
        sm_lbls.append(str(key[i]))
        sm_vals.append(values[i]) 
    else:
        md_lbls.append(str(key[i]))
        md_vals.append(values[i])

    if str(key[i])=="BENIGN":
        benign+=values[i]
    else:
        attack+=values[i]
        
key =[benign,attack]

labels=["BENIGN %"+str(round(benign/(benign+attack),2)*100),
        "ATTACK %"+str(round(attack/(benign+attack),2)*100)]
graph(bg_lbls,bg_vals,"Numbers","Attacks Labels - High number group")
graph(md_lbls,md_vals,"Numbers","Attacks Labels - Medium number group")
graph(sm_lbls,sm_vals,"Numbers","Attacks Labels - Small number group")
graph(labels,key,"Numbers","Attack and Benign Percentage")