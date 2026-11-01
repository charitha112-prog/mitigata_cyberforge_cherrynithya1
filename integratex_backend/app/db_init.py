from app.db import engine, Base
from app import models

if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    print("IntegrateX tables created successfully.")
