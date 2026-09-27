import React, { useState, useRef, useEffect } from 'react';
import {
  Send,
  Sparkles,
  Bot,
  User,
  ShieldAlert,
  Copy,
  Check,
  RefreshCw,
} from 'lucide-react';
import { ThreatAnalysisResult } from '../types';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface CopilotViewProps {
  analysis: ThreatAnalysisResult;
  initialQuery?: string;
  onClearInitialQuery?: () => void;
}

export const CopilotView: React.FC<CopilotViewProps> = ({
  analysis,
  initialQuery,
  onClearInitialQuery,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `Bonjour ! Je suis votre Copilote SOC IA pour votre infrastructure Nebula (Zyxel Nebula Secure Reporter / ATP / USG FLEX).

J'ai analysé votre rapport actuel :
- **Niveau de menace** : ${analysis.threatLevel} (Score : ${analysis.riskScore}/100)
- **Attaques actives** : ${analysis.attackVectors.map((v) => v.name).join(', ')}
- **IPs attaquantes principales** : ${analysis.iocList.filter((i) => i.type === 'IP').slice(0, 3).map((i) => i.value).join(', ') || 'Aucune'}

Posez-moi n'importe quelle question sur l'investigation, la création de règles de filtrage Zyxel, ou la procédure d'arrêt d'urgence.`,
    },
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Handle initial query if passed from log explorer
  useEffect(() => {
    if (initialQuery) {
      sendMessage(initialQuery);
      if (onClearInitialQuery) onClearInitialQuery();
    }
  }, [initialQuery]);

  const sendMessage = async (textToSend: string) => {
    if (!textToSend.trim() || isLoading) return;

    const userMsg: Message = { role: 'user', content: textToSend };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const res = await fetch('/api/chat-copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend,
          history: messages.map((m) => ({
            role: m.role === 'assistant' ? 'model' : 'user',
            content: m.content,
          })),
          currentAnalysis: analysis,
        }),
      });

      if (!res.ok) throw new Error('Erreur réseau');
      const data = await res.json();
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.reply || 'Pas de réponse reçue.' },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            "Une erreur est survenue lors de la communication avec le Copilote IA. Pour bloquer l'attaque en cours, utilisez l'onglet 'Centre de Riposte' pour déployer les règles sur la passerelle Nebula.",
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const quickPrompts = [
    'Quelles adresses IP dois-je bannir en priorité absolue ?',
    'Comment configurer la règle de drop dans Nebula Control Center ?',
    'Donne-moi le script Zyxel ZySH CLI pour isoler le poste interne',
    'Y a-t-il un risque d\'exfiltration de données avéré ?',
    'Rédige une note d\'alerte pour le comité de direction',
  ];

  return (
    <div className="flex flex-col h-[750px] rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl overflow-hidden">
      {/* Header */}
      <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-600/20 border border-cyan-400/30">
            <Sparkles className="w-5 h-5 text-white" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              Copilote IA SOC Nebula
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                Gemini 3.8
              </span>
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Expertise Zyxel ATP / USG Flex & Riposte Cyberdéfense
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            setMessages([
              {
                role: 'assistant',
                content:
                  'Conversation réinitialisée. Comment puis-je vous assister pour sécuriser vos passerelles Nebula ?',
              },
            ]);
          }}
          className="text-xs font-mono text-slate-400 hover:text-white px-2.5 py-1.5 rounded-lg hover:bg-slate-800 transition"
        >
          Effacer
        </button>
      </div>

      {/* Messages Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-5">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex items-start gap-3 ${
              msg.role === 'user' ? 'flex-row-reverse' : ''
            }`}
          >
            {/* Avatar */}
            <div
              className={`w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 ${
                msg.role === 'user'
                  ? 'bg-blue-600 text-white'
                  : 'bg-cyan-950 border border-cyan-800 text-cyan-400'
              }`}
            >
              {msg.role === 'user' ? (
                <User className="w-4 h-4" />
              ) : (
                <Bot className="w-4 h-4" />
              )}
            </div>

            {/* Content Bubble */}
            <div
              className={`max-w-[85%] rounded-2xl p-4 text-xs sm:text-sm leading-relaxed shadow-md relative group ${
                msg.role === 'user'
                  ? 'bg-blue-600 text-white font-medium rounded-tr-sm'
                  : 'bg-slate-950/80 border border-slate-800 text-slate-200 rounded-tl-sm'
              }`}
            >
              <div className="whitespace-pre-wrap font-sans">{msg.content}</div>

              {msg.role === 'assistant' && (
                <button
                  onClick={() => handleCopy(msg.content, idx)}
                  className="absolute top-2 right-2 p-1 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white opacity-0 group-hover:opacity-100 transition"
                  title="Copier la réponse"
                >
                  {copiedIndex === idx ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400 flex items-center justify-center flex-shrink-0 animate-pulse">
              <Sparkles className="w-4 h-4" />
            </div>
            <div className="bg-slate-950/80 border border-slate-800 rounded-2xl rounded-tl-sm p-4 text-xs text-slate-400 flex items-center gap-2">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              <span>Analyse et génération de la riposte en cours...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Quick Prompts */}
      <div className="p-3 bg-slate-950/60 border-t border-slate-800 overflow-x-auto">
        <div className="flex items-center gap-2 whitespace-nowrap">
          <span className="text-[10px] font-mono uppercase text-slate-500 flex-shrink-0">
            Suggestions :
          </span>
          {quickPrompts.map((prompt, i) => (
            <button
              key={i}
              onClick={() => sendMessage(prompt)}
              className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/80 transition"
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Input Bar */}
      <div className="p-4 bg-slate-950 border-t border-slate-800">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            sendMessage(input);
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            placeholder="Posez une question technique sur les logs ou la configuration Nebula..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={isLoading}
            className="flex-1 bg-slate-900 border border-slate-700/80 rounded-xl px-4 py-3 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-sans"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="p-3 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold shadow-md shadow-cyan-600/30 transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};
