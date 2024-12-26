import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

#attack_data = pd.read_csv(r"C:...\attack_modbus.csv")
#benign_data = pd.read_csv(r"C:...\benign_modbus.csv")

attack_data = pd.read_csv(r"C:...\attack_tcp.csv")
benign_data = pd.read_csv(r"C:...\benign_tcp.csv")

attack_data['Label'] = 1  # 1: Attack
benign_data['Label'] = 0  # 0: Benign

merged_data = pd.concat([attack_data, benign_data]).sample(frac=1, random_state=42).reset_index(drop=True)

encoder = LabelEncoder()
merged_data['Flags_encoded'] = encoder.fit_transform(merged_data['Flags'])

selected_features = ['Length', 'SrcPkt', 'SrcBytes', 'DstPkt', 'Sport', 'Dport', 'IP_id', 'Sequence',
                    'Acknowledgment', 'Window', 'Flags_encoded']

# selected_features = ['Transaction_ID', 'Protocol_ID', 'Length', 'Unit_ID', 'Function_Code', 'Ip_id','Sport', 'Chksum']

X = merged_data[selected_features]
y = merged_data['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.99, random_state=42)

with open(r'C:...\Random Forest_TCP_model.pkl', 'rb') as file:
    model = pickle.load(file)

y_pred = model.predict(X_test)

cm = confusion_matrix(y_test, y_pred)

disp = ConfusionMatrixDisplay(confusion_matrix=cm)
disp.plot()
plt.title("Random Forest - Confusion Matrix (TCP)")
plt.show()
