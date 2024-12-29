import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, \
    brier_score_loss, ConfusionMatrixDisplay
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix, precision_recall_curve
import shap


def evaluate_model(X_train, X_test, y_train, y_test, grid_search):
    grid_search.fit(X_train, y_train)
    model = grid_search.best_estimator_
    y_pred = model.predict(X_test)
    print(model)
    print("Model Performance:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred))
    print("Recall:", recall_score(y_test, y_pred))
    print("F1-Score:", f1_score(y_test, y_pred))
    print("Brier Score Loss:", brier_score_loss(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print('\n' + '-'*50 + '\n')
    return model, y_pred


def plot_confusion_matrix_heatmap(model, X_test, y_test, model_name):
    disp = ConfusionMatrixDisplay.from_estimator(model, X_test, y_test, cmap=plt.cm.Blues)
    disp.plot()
    plt.title(f'{model_name} - Confusion Matrix Heatmap (Modbus)')
    plt.show()


def plot_precision_recall_curve(model, X_test, y_test, model_name):
    precision, recall, _ = precision_recall_curve(y_test, model.predict_proba(X_test)[:, 1])
    plt.plot(recall, precision, marker='.')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title(f'{model_name} - Precision-Recall Curve (Modbus)')
    plt.show()


def plot_shap_values(model, X_test, feature_names, model_name):
    explainer = shap.Explainer(model, X_test)
    shap_values = explainer.shap_values(X_test)
    shap.summary_plot(shap_values[0], X_test, feature_names=feature_names, title=f'SHAP Values for {model_name}')


if __name__ == "__main__":
    attack_data = pd.read_csv(r"C:...\attack_tcp.csv")
    benign_data = pd.read_csv(r"C:...\benign_tcp.csv")

    # attack_data = pd.read_csv(r"C:...\attack_modbus.csv")
    # benign_data = pd.read_csv(r"C:...\benign_modbus.csv")

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

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    models = [
        RandomForestClassifier(),
        DecisionTreeClassifier(),
        MLPClassifier()
    ]

    param_grid = [
        {'n_estimators': [10, 50, 100], 'max_features': ['auto', 'sqrt', 'log2']},
        {'criterion': ['gini', 'entropy'], 'max_depth': [None, 10, 20, 30]},
        {'hidden_layer_sizes': [(50, 50, 50), (50, 100, 50), (100,)], 'activation': ['tanh', 'relu'],
         'solver': ['sgd', 'adam'], 'alpha': [0.0001, 0.05], 'learning_rate': ['constant','adaptive']}
    ]

    for model, params in zip(models, param_grid):
        model_name = type(model).__name__
        grid_search = GridSearchCV(model, params, cv=5)
        trained_model, y_pred = evaluate_model(X_train, X_test, y_train, y_test, grid_search)
        # plot_confusion_matrix_heatmap(trained_model, X_test, y_test, model_name)
        # plot_precision_recall_curve(trained_model, X_test, y_test, model_name)
        plot_shap_values(trained_model, X_test, selected_features, model_name)
