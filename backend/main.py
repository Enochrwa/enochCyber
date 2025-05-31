from contextlib import asynccontextmanager
from datetime import datetime
import asyncio
import logging
# from scapy.all import get_if_list # Removed
import psutil # Added
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from multiprocessing import Queue, Manager
import multiprocessing
from queue import Full, Empty
import asyncio
# import psutil # Already imported below, ensure it's fine or consolidate

# Configuration
from app.core.config import settings
from app.middleware.blocker_middleware import BlocklistMiddleware
from app.api.v1.api import api_v1_router
from app.services.prevention.app_blocker import ApplicationBlocker
from app.core.logger import setup_logger
from socket_events import get_socket_app
from app.services.system.monitor import SystemMonitor
from app.services.detection.phishing_blocker import PhishingBlocker

# from app.services.system.malware_detection import activate_cyber_defense


# Database
from sqlalchemy.ext.asyncio import AsyncEngine
from app.database import engine, Base, AsyncSessionLocal, init_db


# Routers
from app.api import (
    users as user_router,
    network as network_router,
    auth as auth_router,
    threats as threat_router,
    system as system_router,
    admin as admin_router,
    ids as ids_router,
)

from api.firewall_api import router as firewall_router
from api.threat_intel_api import router as intel_router
from api.nac_api import router as nac_router
from api.dns_api import router as dns_router
from app.utils.report import (
    get_24h_network_traffic,
    get_daily_threat_summary,
    handle_network_history,
)

# from app.api.ips import get_ips_engine

# Services
from app.services.monitoring.sniffer import PacketSniffer
from app.services.detection.signature import SignatureEngine
from app.services.detection.ids_signature import IdsSignatureEngine
from app.services.ips.engine import EnterpriseIPS, ThreatIntel

# from app.services.ips.adapter import IPSPacketAdapter
from app.services.prevention.firewall import FirewallManager

# from app.services.tasks.autofill_task import run_autofill_task

# Socket.IO
from sio_instance import sio
from packet_sniffer_service import PacketSnifferService
from packet_sniffer_events import PacketSnifferNamespace
from malware_events_namespace import MalwareEventsNamespace # Add this

# from socket_events import start_event_emitter

# Logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
setup_logger("main", "INFO")
logger = logging.getLogger(__name__)

###VULNERABILITY
# scanner = VulnerabilityScanner(sio)
# val_blocker = ThreatBlocker(sio)


async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Initialize FastAPI app first
    app = FastAPI(
        title=settings.PROJECT_NAME,
        docs_url="/api/docs" if settings.DOCS else None,
        redoc_url=None,
    )

    # Initialize database
    try:
        if isinstance(engine, AsyncEngine):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        else:
            raise RuntimeError("Database engine is not asynchronous")
    except Exception as e:
        logger.critical(f"Database initialization failed: {str(e)}")
        raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan for startup and shutdown events."""
        await init_db()
        logger.info("🚀 Starting CyberWatch Security System")
        logger.info("Initializing background services...")

        # Initialize services
        try:
            firewall = FirewallManager(sio)
            app.state.firewall = firewall
            logger.info("FirewallManager initialized and stored in app.state.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize FirewallManager: {e_init}", exc_info=True)
            firewall = None # Ensure it's None if init fails

        try:
            signature_engine = SignatureEngine(sio)
            app.state.signature_engine = signature_engine
            logger.info("SignatureEngine initialized and stored in app.state.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize SignatureEngine: {e_init}", exc_info=True)
            signature_engine = None

        try:
            ids_signature_engine = IdsSignatureEngine(sio)
            app.state.ids_signature_engine = ids_signature_engine
            logger.info("IdsSignatureEngine initialized and stored in app.state.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize IdsSignatureEngine: {e_init}", exc_info=True)
            ids_signature_engine = None

        try:
            blocker = ApplicationBlocker(sio)
            app.state.blocker = blocker
            logger.info("ApplicationBlocker initialized and stored in app.state.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize ApplicationBlocker: {e_init}", exc_info=True)
            blocker = None


        # Initialize packet components INDEPENDENTLY
        manager = Manager() # This itself could fail if resources are extremely low.
        sio_queue = manager.Queue(maxsize=10000)
        output_queue = Queue()

        try:
            sniffer_namespace = PacketSnifferNamespace("/packet_sniffer", sio_queue, app.state)
            sio.register_namespace(sniffer_namespace)
            logger.info("PacketSnifferNamespace registered.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize/register PacketSnifferNamespace: {e_init}", exc_info=True)

        try:
            malware_events_ns = MalwareEventsNamespace("/malware_events")
            sio.register_namespace(malware_events_ns)
            logger.info("Registered /malware_events namespace for EMPDRS communication.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize/register MalwareEventsNamespace: {e_init}", exc_info=True)


        try:
            intel = ThreatIntel()
            await intel.load_from_cache() # This is an awaitable call
            asyncio.create_task(intel.fetch_and_cache_feeds()) # Background task
            logger.info("ThreatIntel initialized and cache loading started.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize ThreatIntel: {e_init}", exc_info=True)
            intel = None

        try:
            ips = EnterpriseIPS(
                "rules.json",
                sio,
                intel, # Relies on intel instance
                multiprocessing.cpu_count(),
                sio_queue,
                output_queue,
            )
            # app.state.ips_engine = ips # Storing ips in app.state if needed by other parts
            logger.info("EnterpriseIPS initialized.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize EnterpriseIPS: {e_init}", exc_info=True)
            ips = None


        try:
            sniffer = PacketSniffer(sio_queue)
            app.state.sniffer = sniffer
            logger.info(f"PacketSniffer instance initialized and stored in app.state.sniffer")
        except Exception as e_init:
            logger.critical(f"Failed to initialize PacketSniffer: {e_init}", exc_info=True)
            sniffer = None


        try:
            sniffer_service = PacketSnifferService(sio, sio_queue)
            app.state.sniffer_service = sniffer_service
            logger.info(f"PacketSnifferService instance initialized and stored in app.state.sniffer_service")
        except Exception as e_init:
            logger.critical(f"Failed to initialize PacketSnifferService: {e_init}", exc_info=True)
            sniffer_service = None


        try:
            monitor = SystemMonitor(sio)
            # app.state.system_monitor = monitor # If needed elsewhere
            logger.info("SystemMonitor initialized.")
        except Exception as e_init:
            logger.critical(f"Failed to initialize SystemMonitor: {e_init}", exc_info=True)
            monitor = None

        # phishing_blocker = PhishingBlocker(sio)
        # phishing_blocker = PhishingBlocker(sio)  # Initialize PhishingBlocker
        # logger.info("PhishingBlocker initialized.")

        # Initialize IPS Adapter
        # ips_adapter = IPSPacketAdapter(ips)
        # await ips_adapter.start()

        # Start database autofill task
        # autofill_task = asyncio.create_task(run_autofill_task(interval=300))

        # Store services in app state

        # app.state.firewall = firewall # Already set if successful
        # app.state.signature_engine = signature_engine # Already set
        # app.state.ids_signature_engine = ids_signature_engine # Already set
        # app.state.phishing_blocker = (
        #     phishing_blocker  # Store PhishingBlocker in app state
        # )
        # app.state.ips_engine = ips # Already set (or should be if ips init is successful)
        # app.state.ips_adapter = ips_adapter
        app.state.db = AsyncSessionLocal # This is a type, not an instance, usually fine.
        # app.state.autofill_task = autofill_task
        # app.state.blocker = blocker # Already set

        # emitter_task = asyncio.create_task(start_event_emitter())  # Pass the factory
        # app.state.emitter_task = emitter_task

        try:
            if sniffer_service:
                await sniffer_service.start()
                logger.info("PacketSnifferService started.")
            else:
                logger.warning("PacketSnifferService not initialized, cannot start.")

            if sniffer:
                await sniffer.start()
                logger.info("PacketSniffer started.")
            else:
                logger.warning("PacketSniffer not initialized, cannot start.")

            if monitor:
                await monitor.start() # SystemMonitor's start method
                logger.info("SystemMonitor started.")
            else:
                logger.warning("SystemMonitor not initialized, cannot start.")

            if ips:
                await ips.start()
                logger.info("EnterpriseIPS started.")
            else:
                logger.warning("EnterpriseIPS not initialized, cannot start.")

            # logger.info("System monitoring started") # Original log, can be refined or removed
            logger.info("All core background services attempted to start.")

        except Exception as e_start_services:
            logger.critical(f"Error during startup of core services: {e_start_services}", exc_info=True)
            # Depending on which service failed, app might be in an unstable state.
            # Consider how to handle this (e.g., prevent app from fully starting if critical services fail)

            # Start packet sniffer with IPS integration

            # Start IPS updates task
            # asyncio.create_task(ips_updates_task(ips))

            # Emit periodic summary
            # @sio.on("request_daily_summary")
            # async def _on_request_summary(sid):
            #     try:
            #         if not monitor.data_queue.empty():
            #             stats = monitor.data_queue.get_nowait()
            #             net24 = get_24h_network_traffic(stats)
            #             threats = get_daily_threat_summary(monitor)
            #             await sio.emit(
            #                 "daily_summary",
            #                 {"network24h": net24, "threatSummary": threats},
            #                 to=sid,
            #             )
            #     except Empty:
            #         pass

            yield

        finally:
            # Shutdown tasks
            logger.info("🛑 Gracefully shutting down...")

            # if hasattr(app.state, "phishing_blocker") and app.state.phishing_blocker:
            #     logger.info("Stopping PhishingBlocker...")
            #     # PhishingBlocker.stop() is an async method
            #     await app.state.phishing_blocker.stop()
            #     logger.info("PhishingBlocker stopped.")

            if monitor:
                await monitor.stop()
            if sniffer:  # sniffer.stop() is synchronous
                # To avoid blocking, it should ideally be run in an executor if it's long,
                # or made async. For now, calling it as is.
                logger.info("Stopping PacketSniffer...")
                sniffer.stop()
                logger.info("PacketSniffer stopped.")
            if sniffer_service:  # sniffer_service.stop() is async
                await sniffer_service.stop()

            # await ips_adapter.stop()
            # autofill_task.cancel()
            await engine.dispose()  # Dispose DB engine
            if ips:  # ips.stop() is async
                await ips.stop()
            # health_status = {
            #             "ips_queue_size": ips.input_queue.qsize(),
            #             "sniffer_packets": sniffer.packet_counter.value,
            #             "memory_usage": psutil.virtual_memory().percent,
            #             "timestamp": datetime.utcnow().isoformat()
            #         }
            # await sio.emit("system_health", health_status)

            # emitter_task.cancel()
            # scanner.stop_silent_monitor()

    # Set the lifespan after app creation
    app.router.lifespan_context = lifespan

    # Configure CORS first to ensure frontend access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add other middlewares
    # app.add_middleware(HTTPSRedirectMiddleware)
    # app.add_middleware(
    #     BlocklistMiddleware,
    #     blocker=(
    #         app.state.blocker
    #         if hasattr(app.state, "blocker")
    #         else ApplicationBlocker(sio)
    #     ),
    # )

    # Register routers
    app.include_router(user_router.router, prefix="/api/users", tags=["Users"])
    app.include_router(network_router.router, prefix="/api/network", tags=["Network"])
    app.include_router(auth_router.router, prefix="/api/auth", tags=["Auth"])
    app.include_router(threat_router.router, prefix="/api/threats", tags=["Threats"])
    app.include_router(system_router.router, prefix="/api/system", tags=["System"])
    app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])
    app.include_router(ids_router.router, prefix="/api/ids", tags=["IDS"])
    app.include_router(firewall_router, prefix="/firewall")
    app.include_router(intel_router, prefix="/intel")
    app.include_router(nac_router, prefix="/nac")
    app.include_router(dns_router, prefix="/dns")
    app.include_router(api_v1_router, prefix="/api/v1", tags=["APIv1"])

    # Health check endpoint
    @app.get("/api/health", include_in_schema=False)
    async def health_check():
        return {"status": "ok"}

    # Mount Socket.IO app
    socket_app = get_socket_app(app)
    app.mount("/socket.io", socket_app)

    return app


# Socket.IO events
@sio.event
async def connect(sid, environ):
    try:
        interfaces_info = psutil.net_if_addrs()
        interfaces = list(interfaces_info.keys())
        logger.info(f"Found interfaces using psutil: {interfaces}")
    except Exception as e:
        logger.error(f"Error getting interfaces using psutil: {e}. Falling back to empty list.")
        interfaces = []
    await sio.emit("interfaces_list", interfaces, to=sid)
    logger.info(f"Sent interfaces list to client {sid[:8]}: {interfaces}")


# @sio.on("get_interfaces")
# async def get_interfaces(sid):
#     interfaces = get_if_list()
#     await sio.emit("interfaces", interfaces, to=sid)


@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid[:8]}...")


# Hypercorn entry point
if __name__ == "__main__":
    import hypercorn.asyncio
    from hypercorn.config import Config

    config = Config()
    config.bind = ["127.0.0.1:8000"]
    config.use_reloader = True

    async def run():
        app = await create_app()  # Properly await the app creation
        await hypercorn.asyncio.serve(app, config)

    try:

        asyncio.run(run())

    except KeyboardInterrupt:
        pass