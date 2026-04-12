import { useContext } from 'react';
import { I18nContext } from '../i18n';

export function useI18n() {
  return useContext(I18nContext);
}
