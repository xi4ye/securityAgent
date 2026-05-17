from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings
from langchain_community.embeddings import DeepSeekEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from loguru import logger
import os

from config.settings import CHROMA_DB_PATH, DEEPSEEK_API_KEY, DEEPSEEK_API_BASE


class KnowledgeBase:
    def __init__(
        self,
        collection_name: str = "security_knowledge",
        persist_directory: str = CHROMA_DB_PATH,
        embedding_model: str = "deepseek-chat"
    ):
        self.collection_name = collection_name
        self.persist_directory = persist_directory
        self.embedding_model = embedding_model

        os.makedirs(persist_directory, exist_ok=True)

        self.embeddings = DeepSeekEmbeddings(
            model="deepseek-embeddings",
            api_key=DEEPSEEK_API_KEY,
            base_url=DEEPSEEK_API_BASE
        )

        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(anonymized_telemetry=False)
        )

        self.vectorstore = Chroma(
            client=self.client,
            collection_name=collection_name,
            embedding_function=self.embeddings
        )

        logger.info(f"KnowledgeBase initialized: {collection_name}")

    def add_documents(
        self,
        documents: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        ids: Optional[List[str]] = None
    ) -> List[str]:
        if not documents:
            return []

        if metadatas is None:
            metadatas = [{"source": "manual"} for _ in documents]

        if ids is None:
            import uuid
            ids = [str(uuid.uuid4()) for _ in documents]

        try:
            self.vectorstore.add_texts(
                texts=documents,
                metadatas=metadatas,
                ids=ids
            )
            logger.info(f"Added {len(documents)} documents to {self.collection_name}")
            return ids
        except Exception as e:
            logger.error(f"Error adding documents: {e}")
            return []

    def load_documents_from_directory(
        self,
        directory_path: str,
        file_extensions: List[str] = [".txt", ".md", ".pdf"]
    ) -> int:
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len
        )

        total_docs = 0
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if any(file.endswith(ext) for ext in file_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()

                        chunks = text_splitter.split_text(content)
                        metadatas = [{
                            "source": file_path,
                            "filename": file
                        } for _ in chunks]

                        self.add_documents(chunks, metadatas)
                        total_docs += len(chunks)
                        logger.info(f"Loaded {file}: {len(chunks)} chunks")
                    except Exception as e:
                        logger.error(f"Error loading {file_path}: {e}")

        return total_docs

    def retrieve(
        self,
        query: str,
        k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        try:
            results = self.vectorstore.similarity_search_with_score(
                query=query,
                k=k,
                filter=filter_metadata
            )

            documents = [doc.page_content for doc, score in results if score < 0.8]
            logger.info(f"Retrieved {len(documents)} relevant documents")
            return documents

        except Exception as e:
            logger.error(f"Error retrieving documents: {e}")
            return []

    def delete_collection(self):
        try:
            self.client.delete_collection(self.collection_name)
            logger.info(f"Deleted collection: {self.collection_name}")
        except Exception as e:
            logger.error(f"Error deleting collection: {e}")


class PolicyKnowledgeBase(KnowledgeBase):
    def __init__(self, persist_directory: str = CHROMA_DB_PATH):
        super().__init__(
            collection_name="policy_knowledge",
            persist_directory=persist_directory
        )


class VulnKnowledgeBase(KnowledgeBase):
    def __init__(self, persist_directory: str = CHROMA_DB_PATH):
        super().__init__(
            collection_name="vulnerability_knowledge",
            persist_directory=persist_directory
        )


class AttckKnowledgeBase(KnowledgeBase):
    def __init__(self, persist_directory: str = CHROMA_DB_PATH):
        super().__init__(
            collection_name="attck_knowledge",
            persist_directory=persist_directory
        )