import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, \
    brier_score_loss, log_loss
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import pickle
import numpy as np


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


def evaluate_model(model, X_train, X_test, y_train, y_test, model_name):
    if isinstance(model, MLPWithHistory):
        model.fit(X_train, y_train, X_test, y_test)
        train_loss_curve = model.train_loss_curve_
        test_loss_curve = model.test_loss_curve_
        train_accuracy_curve = model.train_accuracy_curve_
        test_accuracy_curve = model.test_accuracy_curve_
    else:
        model.fit(X_train, y_train)
        train_loss_curve = None
        test_loss_curve = None
        train_accuracy_curve = None
        test_accuracy_curve = None

    y_pred = model.predict(X_test)
    print(f"{model_name} Model:")
    print("Best Parameters:", model.best_params_ if hasattr(model, 'best_params_') else "N/A")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred))
    print("Recall:", recall_score(y_test, y_pred))
    print("F1-Score:", f1_score(y_test, y_pred))
    print("Brier Score Loss:", brier_score_loss(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print('\n' + '-' * 50 + '\n')
    return model, train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve


def plot_training_history(train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve, model_name,
                          dataset_name):
    if train_loss_curve is not None and test_loss_curve is not None:
        plt.figure()
        plt.plot(train_loss_curve, label='Train Loss')
        plt.plot(test_loss_curve, label='Test Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.title(f'Loss Curves for {model_name} on {dataset_name} Data')
        plt.legend()
        plt.show()

        plt.figure()
        plt.plot(train_accuracy_curve, label='Train Accuracy')
        plt.plot(test_accuracy_curve, label='Test Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.title(f'Accuracy Curves for {model_name} on {dataset_name} Data')
        plt.legend()
        plt.show()


def evaluate_and_save_models(model_name, base_model, param_grid, tcp_data, modbus_data):
    tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test = tcp_data
    modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test = modbus_data

    if model_name == "MLP":
        print(f"Evaluating {model_name} on TCP Data:")
        best_mlp_model = MLPWithHistory(hidden_layer_sizes=(10,), activation='relu', solver='adam', max_iter=50,
                                        random_state=42)
        best_mlp_model, train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve = evaluate_model(
            best_mlp_model, tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test, model_name)

        with open(f'{model_name}_TCP_model.pkl', 'wb') as f:
            pickle.dump(best_mlp_model, f)
        with open(f'{model_name}_TCP_train_loss_curve.pkl', 'wb') as f:
            pickle.dump(train_loss_curve, f)
        with open(f'{model_name}_TCP_test_loss_curve.pkl', 'wb') as f:
            pickle.dump(test_loss_curve, f)
        with open(f'{model_name}_TCP_train_accuracy_curve.pkl', 'wb') as f:
            pickle.dump(train_accuracy_curve, f)
        with open(f'{model_name}_TCP_test_accuracy_curve.pkl', 'wb') as f:
            pickle.dump(test_accuracy_curve, f)

        plot_training_history(train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve, model_name,
                              "TCP")

        print(f"Evaluating {model_name} on Modbus Data:")
        best_mlp_model = MLPWithHistory(hidden_layer_sizes=(10,), activation='relu', solver='adam', max_iter=50,
                                        random_state=42)
        best_mlp_model, train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve = evaluate_model(
            best_mlp_model, modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test, model_name)

        with open(f'{model_name}_Modbus_model.pkl', 'wb') as f:
            pickle.dump(best_mlp_model, f)
        with open(f'{model_name}_Modbus_train_loss_curve.pkl', 'wb') as f:
            pickle.dump(train_loss_curve, f)
        with open(f'{model_name}_Modbus_test_loss_curve.pkl', 'wb') as f:
            pickle.dump(test_loss_curve, f)
        with open(f'{model_name}_Modbus_train_accuracy_curve.pkl', 'wb') as f:
            pickle.dump(train_accuracy_curve, f)
        with open(f'{model_name}_Modbus_test_accuracy_curve.pkl', 'wb') as f:
            pickle.dump(test_accuracy_curve, f)

        plot_training_history(train_loss_curve, test_loss_curve, train_accuracy_curve, test_accuracy_curve, model_name,
                              "Modbus")
    else:
        grid_search = GridSearchCV(estimator=base_model, param_grid=param_grid, cv=3, scoring='accuracy', n_jobs=-1)

        print(f"Evaluating {model_name} on TCP Data:")
        best_tcp_model, _, _, _, _ = evaluate_model(grid_search, tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test,
                                                    model_name)
        with open(f'{model_name}_TCP_model.pkl', 'wb') as f:
            pickle.dump(best_tcp_model, f)

        print(f"Evaluating {model_name} on Modbus Data:")
        best_modbus_model, _, _, _, _ = evaluate_model(grid_search, modbus_X_train, modbus_X_test, modbus_y_train,
                                                       modbus_y_test, model_name)
        with open(f'{model_name}_Modbus_model.pkl', 'wb') as f:
            pickle.dump(best_modbus_model, f)


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

random_forest_param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10]
}

decision_tree_param_grid = {
    'criterion': ['gini', 'entropy'],
    'max_depth': [None, 10, 20, 30],
    'min_samples_split': [2, 5, 10]
}

evaluate_and_save_models("Random Forest", RandomForestClassifier(random_state=42), random_forest_param_grid,
                         (tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test),
                         (modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test))
evaluate_and_save_models("Decision Tree", DecisionTreeClassifier(random_state=42), decision_tree_param_grid,
                         (tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test),
                         (modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test))
evaluate_and_save_models("MLP", None, None, (tcp_X_train, tcp_X_test, tcp_y_train, tcp_y_test),
                         (modbus_X_train, modbus_X_test, modbus_y_train, modbus_y_test))

