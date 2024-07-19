import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn import metrics
from xgboost import XGBClassifier
from sklearn.feature_selection import RFE, SelectFromModel
from sklearn.linear_model import LogisticRegression
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from collections import Counter

full = pd.read_csv("dataset_full.csv")
small = pd.read_csv("dataset_small.csv")

data = pd.concat([full,small])
data.reset_index(drop=True, inplace=True)

data = data.drop(data[np.isnan(data['url_google_index'])].index, axis=0)

X = data.drop('phishing', axis=1)
y = data['phishing']

# splitting the datset
X_train, X_test, y_train, y_test = train_test_split(X,y,test_size=0.25, random_state=42)


# most relevant features

# RFE with XGBoost
xgb_model = xgb.XGBClassifier()
rfe_xgb = RFE(estimator=xgb_model, n_features_to_select=50, step=10)
rfe_xgb.fit(X_train, y_train)
selected_features_rfe_xgb = np.array(X_train.columns)[rfe_xgb.support_]

# XGBoost feature importance
xgb_model.fit(X_train, y_train)
xgb_feature_importance = xgb_model.feature_importances_
selected_features_xgb = X_train.columns[xgb_feature_importance > 0.01]

# Random Forest feature importance
rf_model = RandomForestClassifier()
rf_model.fit(X_train, y_train)
rf_feature_importance = rf_model.feature_importances_
selected_features_rf = X_train.columns[rf_feature_importance > 0.01]

# L1 regularization (Lasso)
lasso = LogisticRegression(penalty='l1', solver='liblinear', C=0.1)
lasso.fit(X_train, y_train)
selected_features_lasso = X_train.columns[lasso.coef_[0] != 0]

# Combine the selected features from different methods
all_selected_features = np.concatenate([selected_features_rfe_xgb, selected_features_xgb,
                                        selected_features_rf, selected_features_lasso])

# Find the features present in most of the results
feature_counts = Counter(all_selected_features)
most_common_features = [feature for feature, count in feature_counts.items() if count > 1]

# scaling the features
scaler = StandardScaler()
xgb_model = XGBClassifier(n_estimators=1000, objective='binary:logistic', random_state=42)

pipeline = Pipeline([
    ('scaler', scaler),
    ('xgb', xgb_model)
])

X_train = X_train[most_common_features]
X_test = X_test[most_common_features]

pipeline.fit(X_train, y_train)

# validation phase
predictions = pipeline.predict(X_test)
print(f'Accuracy of the model is : {metrics.accuracy_score(y_true=y_test, y_pred=predictions)}')

cm = metrics.confusion_matrix(y_test,predictions)
print(cm)

TP = cm[1,1]
TN = cm[0,0]
FN = cm[1,0]
FP = cm[0,1]

sens = TP/(TP+FN)
print('Sensitivity is {}'.format(sens))

speci = TN/(TN+FP)
print('Specificity is {}'.format(speci))

prev = (TP+FN)/(TN+FP+FN+TN)
print('Prevalence is {}'.format(prev))

prob_ve = (TN+FP)/(TP+FP+FN+TN)
print('-ve Predicted probability is {}'.format(prob_ve))

true_accu = sens * prev + speci * prob_ve
print('True accuracy is {}'.format(true_accu))

f1_score = metrics.f1_score(y_true=y_test, y_pred=predictions)
print(f'F1-Score of the model is : {f1_score}')

pickle.dump(pipeline, open('pipeline.pkl', 'wb'))
pickle.dump(most_common_features, open('features.pkl', 'wb'))