import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt

# -----------------------
# Load model + dataset
# -----------------------
model = joblib.load("phishing_Model.pkl")["model"]  # <── FIXED LINE
df = pd.read_csv("data/6.FinalDataset.csv")

X = df.iloc[:, :-1]   # feature columns only

# -----------------------
# SHAP Explainer
# -----------------------
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X)

# -----------------------
# Summary Plot
# -----------------------
shap.summary_plot(shap_values, X, show=False)
plt.tight_layout()
plt.savefig("Images/SHAP_summary.png", dpi=300, bbox_inches="tight")
plt.close()

# -----------------------
# Bar Plot
# -----------------------
shap.summary_plot(shap_values, X, plot_type="bar", show=False)
plt.tight_layout()
plt.savefig("Images/SHAP_bar.png", dpi=300, bbox_inches="tight")
plt.close()

print("\n✔ SHAP Summary & Bar Plots Saved Successfully!")
