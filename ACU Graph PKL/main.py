import pickle
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neural_network._base import log_loss
from sklearn.preprocessing import LabelEncoder
from sklearn.neural_network import MLPClassifier
import numpy as np


class MLPWithHistory(MLPClassifier):
    def fit(self, X_train, y_train, X_test, y_test):
        self.train_loss_curve_ = []
        self.test_loss_curve_ = []
        self.train_accuracy_curve_ = []
        self.test_accuracy_curve_ = []

        for _ in range(self.max_iter):
            super().partial_fit(X_train, y_train, classes=np.unique(y_train))
            self.train_loss_curve_.append(log_loss(y_train, self.predict_proba(X_train)))
            self.test_loss_curve_.append(log_loss(y_test, self.predict_proba(X_test)))
            self.train_accuracy_curve_.append(super().score(X_train, y_train))
            self.test_accuracy_curve_.append(super().score(X_test, y_test))

        return self


def load_model(file_path):
    with open(file_path, 'rb') as f:
        model = pickle.load(f)
    return model


def plot_roc_curves(models, X_test, y_test, model_names, dataset_name):
    plt.figure()

    for model, model_name in zip(models, model_names):
        y_pred_prob = model.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_pred_prob)
        roc_auc = auc(fpr, tpr)
        plt.plot(fpr, tpr, lw=2, label=f'{model_name} (AUC = {roc_auc:.2f})')

    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontweight='bold', fontsize=12, labelpad=10)
    plt.ylabel('True Positive Rate', fontweight='bold', fontsize=12, labelpad=10)
    plt.title(f'ROC Curve for {dataset_name} Data', fontweight='bold', fontsize=14, pad=20)
    plt.legend(loc='lower right')
    plt.show()


def load_and_prepare_data_tcp(attack_path, benign_path, selected_features):
    attack_data = pd.read_csv(attack_path)
    benign_data = pd.read_csv(benign_path)

    attack_data['Label'] = 1  # 1: Attack
    benign_data['Label'] = 0  # 0: Benign

    merged_data = pd.concat([attack_data, benign_data]).sample(frac=1, random_state=42).reset_index(drop=True)

    encoder = LabelEncoder()
    merged_data['Flags_encoded'] = encoder.fit_transform(merged_data['Flags'])

    X = merged_data[selected_features]
    y = merged_data['Label']

    return train_test_split(X, y, test_size=0.3, random_state=42)


def load_and_prepare_data_modbus(attack_path, benign_path, selected_features):
    attack_data = pd.read_csv(attack_path)
    benign_data = pd.read_csv(benign_path)

    attack_data['Label'] = 1  # 1: Attack
    benign_data['Label'] = 0  # 0: Benign

    merged_data = pd.concat([attack_data, benign_data]).sample(frac=1, random_state=42).reset_index(drop=True)

    X = merged_data[selected_features]
    y = merged_data['Label']

    return train_test_split(X, y, test_size=0.3, random_state=42)


tcp_model_path_MLP = r"C:...\MLP_TCP_model.pkl"
modbus_model_path_MLP = r"C:...\MLP_Modbus_model.pkl"

tcp_model_path_RF = r"C:...\Random Forest_TCP_model.pkl"
modbus_model_path_RF = r"C:...\Random Forest_Modbus_model.pkl"

tcp_model_path_DT = r"C:...\Decision Tree_TCP_model.pkl"
modbus_model_path_DT = r"C:...\Decision Tree_Modbus_model.pkl"

tcp_model_MLP = load_model(tcp_model_path_MLP)
modbus_model_MLP = load_model(modbus_model_path_MLP)

tcp_model_RF = load_model(tcp_model_path_RF)
modbus_model_RF = load_model(modbus_model_path_RF)

tcp_model_DT = load_model(tcp_model_path_DT)
modbus_model_DT = load_model(modbus_model_path_DT)

tcp_selected_features = ['Length', 'SrcPkt', 'SrcBytes', 'DstPkt', 'Sport', 'Dport', 'IP_id', 'Sequence',
                         'Acknowledgment', 'Window', 'Flags_encoded']
tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test = load_and_prepare_data_tcp(
    r"C:...\attack_tcp.csv",
    r"C:...\benign_tcp.csv",
    tcp_selected_features
)

modbus_selected_features = ['Transaction_ID', 'Protocol_ID', 'Length', 'Unit_ID', 'Function_Code', 'Ip_id', 'Sport',
                            'Chksum']
modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test = load_and_prepare_data_modbus(
    r"C:...\attack_modbus.csv",
    r"C:...\benign_modbus.csv",
    modbus_selected_features
)

tcp_models = [tcp_model_MLP, tcp_model_RF, tcp_model_DT]
tcp_model_names = ['MLP', 'Random Forest', 'Decision Tree']

modbus_models = [modbus_model_MLP, modbus_model_RF, modbus_model_DT]
modbus_model_names = ['MLP', 'Random Forest', 'Decision Tree']

plot_roc_curves(tcp_models, tcp_X_test, tcp_y_test, tcp_model_names, 'TCP')
plot_roc_curves(modbus_models, modbus_X_test, modbus_y_test, modbus_model_names, 'Modbus')
