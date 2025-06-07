import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const CyberLoader = ({ isLoading = true }) => {
  if (!isLoading) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950 overflow-hidden"
      >
        {/* Animated background grid */}
        <div className="absolute inset-0">
          <motion.div
            className="w-full h-full opacity-20"
            animate={{ backgroundPosition: ['0px 0px', '50px 50px', '0px 0px'] }}
            transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
            style={{
              backgroundImage: `
                radial-gradient(circle at 20% 50%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(34, 197, 94, 0.15) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(168, 85, 247, 0.15) 0%, transparent 50%),
                linear-gradient(rgba(59, 130, 246, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(59, 130, 246, 0.05) 1px, transparent 1px)
              `,
              backgroundSize: '100% 100%, 100% 100%, 100% 100%, 40px 40px, 40px 40px',
            }}
          />
        </div>

        {/* Radar animation */}
        <motion.div
          className="absolute inset-0 pointer-events-none flex items-center justify-center"
          animate={{ rotate: 360 }}
          transition={{ duration: 12, repeat: Infinity, ease: 'linear' }}
        >
          <div className="relative">
            {[300, 250, 200].map((size, i) => (
              <motion.div
                key={i}
                className="absolute -translate-x-1/2 -translate-y-1/2 rounded-full border border-blue-400/20"
                style={{ width: size, height: size, left: '50%', top: '50%' }}
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 3 + i, repeat: Infinity, ease: 'easeInOut', delay: i * 0.5 }}
              />
            ))}
            <div className="absolute top-0 left-1/2 w-0.5 h-36 bg-gradient-to-b from-blue-400/80 via-emerald-400/60 to-transparent transform -translate-x-0.5" />
          </div>
        </motion.div>

        {/* Loader message */}
        <div className="z-10 text-center text-white px-6">
          <motion.h2
            className="text-2xl sm:text-3xl md:text-4xl font-semibold tracking-wide"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
          >
            Starting background services...
          </motion.h2>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default CyberLoader;
