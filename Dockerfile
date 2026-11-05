FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY app ./app
COPY eval ./eval
RUN pip install --no-cache-dir -e .
EXPOSE 8501
CMD ["sh", "-c", "phi-gov load && phi-gov scan && streamlit run app/streamlit_app.py --server.address=0.0.0.0"]
