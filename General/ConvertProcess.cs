using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Models;

namespace General
{
    public static class ConvertProcess
    {
        public static OperationResult<T> Deserialize<T>(string SourceData)
        {
            OperationResult<T> op = new OperationResult<T>();
            List<string> errors = new List<string>();

            try
            {
                var t = JsonConvert.DeserializeObject<T>(SourceData,
                    new JsonSerializerSettings
                    {
                        Error = delegate (object sender, ErrorEventArgs args)
                        {
                            errors.Add(args.ErrorContext.Error.Message);
                            args.ErrorContext.Handled = true;
                        },
                        Converters = { new IsoDateTimeConverter() }
                    });

                op.Data = t;
            }
            catch (Exception ex)
            {
                op.Result = false;
                op.Message = ex.Message;
            }
            finally
            {
                if (errors.Count > 0)
                {
                    op.Result = false;
                    op.Message = string.Join(Environment.NewLine, errors.ToArray());
                }
            }

            return op;
        }
    }
}
